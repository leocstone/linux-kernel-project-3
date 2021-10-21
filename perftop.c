#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/types.h>
#include <linux/kprobes.h>
#include <linux/hashtable.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/jhash.h>
#include <linux/spinlock.h>
#include <linux/processor.h>
#include <linux/sched/task_stack.h>
#include <linux/rbtree.h>

#include <asm/msr.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Leo Stone");
MODULE_DESCRIPTION("Project 3");

static char pick_next_task_fair_symbol[64] = "pick_next_task_fair";

static char kallsyms_lookup_name_symbol[64] = "kallsyms_lookup_name";
typedef unsigned long (*kallsyms_lookup_name_function)(const char*);
kallsyms_lookup_name_function kallsyms_lookup_name_ptr = NULL;

static char kallsyms_lookup_symbol[64] = "kallsyms_lookup";
typedef const char* (*kallsyms_lookup_function)(unsigned long, unsigned long*, unsigned long*, char**, char*);
static kallsyms_lookup_function kallsyms_lookup_ptr = NULL;

typedef unsigned int (*stack_trace_save_tsk_function)(struct task_struct*, unsigned long*, unsigned int, unsigned int);
static stack_trace_save_tsk_function stack_trace_save_tsk_ptr = NULL;
static char stack_trace_save_tsk_symbol[64] = "stack_trace_save_tsk";

#define MAX_TRACE 64
#define MY_JHASH_INITVAL 0x42fa5542

struct stack_trace {
	unsigned long trace[MAX_TRACE];
	unsigned int trace_length;
};

/*
 * Tree definitions
 */
static DEFINE_SPINLOCK(tree_lock);
static struct rb_root task_tree = RB_ROOT;
struct rb_entry {
        struct rb_node node;
        unsigned long long cycles_running;
	unsigned long long last_tsc;
	struct stack_trace st;
	int is_user;
};

static void insert_to_task_tree(struct rb_entry *new_entry)
{
	struct rb_node **link = &task_tree.rb_node;
        struct rb_node *parent = NULL;
        struct rb_entry *entry;

        while(*link) {
                parent = *link;
                entry = rb_entry(parent, struct rb_entry, node);
                if(new_entry->cycles_running < entry->cycles_running) {
                        link = &parent->rb_left;
                } else {
                        link = &parent->rb_right;
                }
        }

        rb_link_node(&new_entry->node, parent, link);
        rb_insert_color(&new_entry->node, &task_tree);
}

static int traces_equal(struct stack_trace *t1, struct stack_trace *t2)
{
    int i = 0;
    if(t1->trace_length != t2->trace_length) {
        return 0;
    }
    for(; i < t1->trace_length; i++) {
        if(t1->trace[i] != t2->trace[i]) {
            return 0;
        }
    }
    return 1;
}

static void destroy_tree_and_free(void)
{
	struct rb_node *iterator = rb_first(&task_tree);
	struct rb_entry *tmp;
	while(iterator) {
		tmp = rb_entry(iterator, struct rb_entry, node);
		iterator = rb_next(iterator);
		rb_erase(&tmp->node, &task_tree);
		kfree(tmp);
	}
}

/*
 * Modified implementation of stack_trace_save_user to allow task parameter
 */
struct stack_frame_user {
	const void __user	*next_fp;
	unsigned long		ret_addr;
};

static int
copy_stack_frame(const struct stack_frame_user __user *fp,
		 struct stack_frame_user *frame)
{
	int ret;

	if (__range_not_ok(fp, sizeof(*frame), TASK_SIZE))
		return 0;

	ret = 1;
	pagefault_disable();
	if (__get_user(frame->next_fp, &fp->next_fp) ||
	    __get_user(frame->ret_addr, &fp->ret_addr))
		ret = 0;
	pagefault_enable();

	return ret;
}

void arch_stack_walk_user(stack_trace_consume_fn consume_entry, void *cookie,
			  const struct pt_regs *regs)
{
	const void __user *fp = (const void __user *)regs->bp;

	if (!consume_entry(cookie, regs->ip))
		return;

	while (1) {
		struct stack_frame_user frame;

		frame.next_fp = NULL;
		frame.ret_addr = 0;
		if (!copy_stack_frame(fp, &frame))
			break;
		if ((unsigned long)fp < regs->sp)
			break;
		if (!frame.ret_addr)
			break;
		if (!consume_entry(cookie, frame.ret_addr))
			break;
		fp = frame.next_fp;
	}
}

struct stacktrace_cookie {
	unsigned long	*store;
	unsigned int	size;
	unsigned int	skip;
	unsigned int	len;
};

static bool custom_stack_trace_consume_entry(void *cookie, unsigned long addr)
{
	struct stacktrace_cookie *c = cookie;

	if (c->len >= c->size)
		return false;

	if (c->skip > 0) {
		c->skip--;
		return true;
	}
	c->store[c->len++] = addr;
	return c->len < c->size;
}

static unsigned int stack_trace_save_user_tsk(struct task_struct *tsk, unsigned long *store, unsigned int size, unsigned int skipnr)
{
	stack_trace_consume_fn consume_entry = custom_stack_trace_consume_entry;
	struct stacktrace_cookie c = {
		.store	= store,
		.size	= size,
	};
	mm_segment_t fs;

	/* Trace user stack if not a kernel thread */
	if (current->flags & PF_KTHREAD)
		return 0;

	fs = force_uaccess_begin();
	arch_stack_walk_user(consume_entry, &c, task_pt_regs(tsk));
	force_uaccess_end(fs);

	return c.len;
}

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct rb_entry *new_entry;
	u32 trace_jhash;
	struct rb_node *iterator;
	struct rb_entry *tmp;
	/*
	 * Get second parameter to pick_next_task_fair from register parameter 2 (si on x86-64)
	 */
	struct task_struct *prev = (struct task_struct*)regs->si;
	if(prev == NULL)
		return 0;
	/*
	 * Find this task's entry in the hash table
	 */
	spin_lock(&tree_lock);

	/*
	 * Get the stack trace
	 */
	new_entry = (struct rb_entry*)kmalloc(sizeof(struct rb_entry), GFP_ATOMIC);
	new_entry->is_user = (prev->mm != NULL);
	if(new_entry->is_user) {
                new_entry->st.trace_length = stack_trace_save_user_tsk(prev, new_entry->st.trace, MAX_TRACE, 0);
        } else {
                new_entry->st.trace_length = stack_trace_save_tsk_ptr(prev, new_entry->st.trace, MAX_TRACE, 0);
        }
	/*
	 * Hash stack trace
	 */
	trace_jhash = jhash(new_entry->st.trace, sizeof(unsigned long) * new_entry->st.trace_length, MY_JHASH_INITVAL);
	/*
	 * Search for the scheduled stack trace
	 */
	iterator = rb_first(&task_tree);
        while(iterator) {
                tmp = rb_entry(iterator, struct rb_entry, node);
                if(traces_equal(&tmp->st, &new_entry->st)) {
			/*
			 * Update the old node's counter if valid
			 */
			if(tmp->last_tsc != 0) {
                                tmp->cycles_running += (rdtsc() - tmp->last_tsc);
                                tmp->last_tsc = 0;
                        }
			/*
			 * Copy the old data to the new node
			 */
			new_entry->cycles_running = tmp->cycles_running;
			new_entry->last_tsc = 0;

			/*
			 * Swap out the nodes
			 */
			rb_erase(iterator, &task_tree);
			kfree(iterator);
			insert_to_task_tree(new_entry);
			spin_unlock(&tree_lock);
			return 0;
		}
		iterator = rb_next(iterator);
        }

	/*
	 * Create a new entry
	 */
	new_entry->cycles_running = 0;
	new_entry->last_tsc = 0;
        insert_to_task_tree(new_entry);
	spin_unlock(&tree_lock);
	return 0;
}
NOKPROBE_SYMBOL(entry_handler);

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct rb_entry *new_entry;
	u32 trace_jhash;
	struct rb_node *iterator;
	struct rb_entry *tmp;
	struct task_struct *task = (struct task_struct*)regs_return_value(regs);
	if(task == NULL)
		return 0;
	/*
	 * All paths modify the hash table, so acquire spinlock
	 */
	spin_lock(&tree_lock);
	
	/*
	 * Get the stack trace
	 */
	new_entry = (struct rb_entry*)kmalloc(sizeof(struct rb_entry), GFP_ATOMIC);
	new_entry->is_user = (task->mm != NULL);
	if(new_entry->is_user) {
		new_entry->st.trace_length = stack_trace_save_user_tsk(task, new_entry->st.trace, MAX_TRACE, 0);
	} else {
		new_entry->st.trace_length = stack_trace_save_tsk_ptr(task, new_entry->st.trace, MAX_TRACE, 0);
	}

	/*
	 * Hash stack trace
	 */
	trace_jhash = jhash(new_entry->st.trace, sizeof(unsigned long) * new_entry->st.trace_length, MY_JHASH_INITVAL);
	/*
	 * Search for the scheduled stack trace
	 */
	iterator = rb_first(&task_tree);
        while(iterator) {
                tmp = rb_entry(iterator, struct rb_entry, node);
                if(traces_equal(&tmp->st, &new_entry->st)) {
			/*
			 * If the task hasn't been scheduled in yet, make a new timestamp
			 * indicating when it was scheduled in
			 */
			if(tmp->last_tsc == 0) {
				tmp->last_tsc = rdtsc();
			}
			spin_unlock(&tree_lock);
                        return 0;
                }
                iterator = rb_next(iterator);
        }

	/*
	 * The scheduled task wasn't in the tree, so add the new entry instead
	 * of freeing it
	 */
	new_entry->last_tsc = rdtsc();
	new_entry->cycles_running = 0;
	insert_to_task_tree(new_entry);
	spin_unlock(&tree_lock);
	return 0;
}
NOKPROBE_SYMBOL(ret_handler);

static struct kretprobe sched_retprobe = {
	.handler		= ret_handler,
    	.entry_handler		= entry_handler,
	.data_size		= 0,
	.maxactive		= 20,
};

static struct kprobe kallsyms_probe = {
	.symbol_name	= kallsyms_lookup_name_symbol,
};

static int __kprobes kallsyms_pre(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

static void __kprobes kallsyms_post(struct kprobe *kp, struct pt_regs *regs, unsigned long flags)
{
	/* nothing */
}

static int perftop_proc_show(struct seq_file *m, void *v)
{
	int i = 0;
	int j = 0;
	unsigned long symbol_size, symbol_offset;
	char *module_name = NULL;
	char *current_symbol = kmalloc(sizeof(char) * KSYM_NAME_LEN, GFP_ATOMIC);
	
	struct rb_node *iterator = rb_last(&task_tree);
        struct rb_entry *tmp;
        while(iterator && i < 20) {
                tmp = rb_entry(iterator, struct rb_entry, node);
                i++;
		seq_printf(m, "Rank %d scheduled task:\n", i);
		seq_printf(m, "Jenkins hash:\t%08x\n", jhash(tmp->st.trace, tmp->st.trace_length, MY_JHASH_INITVAL));
		seq_printf(m, "Cycles run:\t%llu (TSC ticks)\n", tmp->cycles_running);
		seq_printf(m, "Stack trace:\n");
		j = 0;
		if(tmp->is_user) {
                	for(; j < tmp->st.trace_length && j < 4; j++) {
                        	seq_printf(m, "\t%p\n", (void*)tmp->st.trace[j]);
                	}
            	} else {
                	for(; j < tmp->st.trace_length && j < 4; j++) {
                        	seq_printf(m, "\t%s\n", kallsyms_lookup_ptr(tmp->st.trace[j], &symbol_size, &symbol_offset, &module_name, current_symbol));
                	}
            	}
		if(i < 20)
			seq_printf(m, "\n");
                iterator = rb_prev(iterator);
        }

	kfree(current_symbol);
	return 0;
}

static int perftop_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, perftop_proc_show, NULL);
}

static const struct proc_ops perftop_proc_fops = {
	.proc_open = perftop_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static int __init perftop_init(void)
{
	int ret;
	
	/* Use a kprobe to get the address of kallsyms_lookup_name */
	kallsyms_probe.pre_handler = kallsyms_pre;
	kallsyms_probe.post_handler = kallsyms_post;
	kallsyms_probe.offset = 0;
	kallsyms_probe.addr = 0;
	ret = register_kprobe(&kallsyms_probe);
	if(ret < 0) {
		pr_err("register_kprobe returned %d\n", ret);
		return -1;
	}
	pr_info("kprobe installed at %p\n", kallsyms_probe.addr);
	pr_info("offset: %d\n", kallsyms_probe.offset);
	kallsyms_lookup_name_ptr = (kallsyms_lookup_name_function)kallsyms_probe.addr;
	pr_info("kallsyms_lookup_name at: %p\n", kallsyms_lookup_name_ptr);

	unregister_kprobe(&kallsyms_probe);

	/* Get the address of the non-exported functions */
    	stack_trace_save_tsk_ptr = (stack_trace_save_tsk_function)kallsyms_lookup_name_ptr(stack_trace_save_tsk_symbol);
    	pr_info("Got pointer to stack_trace_save_tsk: %p\n", stack_trace_save_tsk_ptr);

	kallsyms_lookup_ptr = (kallsyms_lookup_function)kallsyms_lookup_name_ptr(kallsyms_lookup_symbol);

	/* Create the /proc module */
	proc_create("perftop", 0, NULL, &perftop_proc_fops);

	/*
	 * Install the kprobe on pick_next_task_fair
	 */	
	sched_retprobe.kp.symbol_name = pick_next_task_fair_symbol;

	ret = register_kretprobe(&sched_retprobe);
	if(ret < 0) {
		pr_err("register_kretprobe returned %d\n", ret);
		return -1;
	}
	pr_info("kretprobe installed at %p\n", sched_retprobe.kp.addr);

	return 0;
}

static void __exit perftop_exit(void)
{
	remove_proc_entry("perftop", NULL);

	unregister_kretprobe(&sched_retprobe);

	pr_info("Missed probing %d instances of %s\n", sched_retprobe.nmissed, sched_retprobe.kp.symbol_name);

	destroy_tree_and_free();
}

module_init(perftop_init);
module_exit(perftop_exit);
