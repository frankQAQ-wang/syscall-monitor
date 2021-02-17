all:
	@echo "generate syscall table"
	@ausyscall --dump | awk '{if(NR!=1)print "_S("$$1", \""$$2"\")"}' > syscall_table.h
	@echo cc sysmond
	@gcc -g -o sysmond sysmond.c
	@echo cc sysmonctl
	@gcc -g -o sysmonctl sysmonctl.c
	@/bin/bash ./completion.sh
clean:
	rm sysmond sysmonctl syscall_table.h
