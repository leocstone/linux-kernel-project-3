## [M1: point 1]
#  Explain following in here
#  The MODULE variable defines the filenames for the source and binary files
#  used in compilation. Our source is located in ex3.c, and we want to build
#  ex3.ko, so it's set to ex3.
MODULE	 = perftop

## [M2: point 1]
#  Explain following in here
#  We want to add the filename for our kernel module's object file
#  to the obj-m variable so that it gets linked into a .ko file
#  by the kernel's makefile. 
obj-m += $(MODULE).o

## [M3: point 1]
#  Explain following in here
#  KERNELDIR is supposed to be the directory containing kernel symbols for
#  the kernel version we're currently running. $(shell uname -r) will
#  evaluate to the version of the currently running kernel (ex: 5.13.0),
#  so the /lib/modules/<kernel version>/build directory should contain
#  the kernel symbols we need to link against to build a module for
#  our kernel version.
KERNELDIR ?= /lib/modules/$(shell uname -r)/build

## [M4: point 1]
#  Explain following in here
#  The pwd command prints the current working directory, so $(shell pwd)
#  will evaluate to a string containing the current directory.
PWD := $(shell pwd)

## [M5: point 1]
#  Explain following in here
#  The all recipe will build our kernel module
all: $(MODULE)


## [M6: point 1]
#  Explain following in here
#  This recipe will produce a .o file for every dependency in our all recipe.
#  The last action line compiles the first dependency into the target of 
#  each dependency in our all recipe. 
%.o: %.c
	@echo "  CC      $<"
	@$(CC) -c $< -o $@

## [M7: point 1]
#  Explain following in here
#  To make our module, we have to change directories to the directory
#  containing our kernel source (which is what the -C option does). 
$(MODULE):
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

## [M8: point 1]
#  Explain following in here
#  The clean recipe will remove any files produced by the
#  compiler during the build process, leaving only the source code 
#  (and forcing a complete rebuild of everything).
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
