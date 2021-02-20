all:
	make -C module all
	make -C process all
install:
	mkdir /lib/modules/$(shell uname -r)/sysmon
	cp module/syscall_monitor.ko /lib/modules/$(shell uname -r)/sysmon
	depmod
	cp process/sysmond /usr/sbin/
	cp process/sysmonctl /usr/bin/
	cp process/sysmonctl.cmp /usr/share/bash-completion/completions/sysmonctl
	cp sysmon.service /lib/systemd/system/
	systemctl daemon-reload
	systemctl enable sysmon
uninstall:
	rm -r /lib/modules/$(shell uname -r)/sysmon
	depmod
	rm /usr/sbin/sysmond
	rm /usr/bin/sysmonctl
	rm /usr/share/bash-completion/completions/sysmonctl
	rm /lib/systemd/system/sysmon.service
	systemctl daemon-reload
clean:
	make -C module clean
	make -C process clean
