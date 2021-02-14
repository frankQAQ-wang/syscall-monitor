all:
	make -C module all
	make -C process all
run:
	insmod module/syscall_monitor.ko
	process/sysmond &> /dev/null &
clean:
	make -C module clean
	make -C process clean
