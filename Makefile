all:
	make -C module all
	make -C process all
install:
	mkdir ${DESTDIR}/usr/lib/modules/$(shell uname -r)/sysmon
	cp module/syscall_monitor.ko ${DESTDIR}/lib/modules/$(shell uname -r)/sysmon
	depmod
	cp process/sysmond ${DESTDIR}/usr/sbin/
	cp process/sysmonctl ${DESTDIR}/usr/bin/
	cp process/sysmonctl.cmp ${DESTDIR}/etc/bash_completion.d/sysmonctl
	cp sysmon.service ${DESTDIR}/usr/lib/systemd/system/
	systemctl daemon-reload
	systemctl enable sysmon
uninstall:
	rm -r ${DESTDIR}/usr/lib/modules/$(shell uname -r)/sysmon
	depmod
	rm ${DESTDIR}/usr/sbin/sysmond
	rm ${DESTDIR}/usr/bin/sysmonctl
	rm ${DESTDIR}/etc/bash_completion.d/sysmonctl
	rm ${DESTDIR}/usr/lib/systemd/system/sysmon.service
	systemctl daemon-reload
rpm:
	rpmbuild -bb syscall_monitor.spec
clean:
	make -C module clean
	make -C process clean
