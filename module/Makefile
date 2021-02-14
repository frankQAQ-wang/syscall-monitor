obj-m := syscall_monitor.o
sched_top-objs := syscall_monitor.o
KERNELBUILD :=/lib/modules/$(shell uname -r)/build
all:
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:
	make -C $(KERNELBUILD) M=$(shell pwd) modules clean
