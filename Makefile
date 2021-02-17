all:
	make -C module all
	make -C process all
run:
	insmod module/syscall_monitor.ko
	process/sysmond &> /dev/null &
	cp process/sysmonctl.cmp /usr/share/bash-completion/completions/
clean:
	make -C module clean
	make -C process clean
