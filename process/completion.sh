#!/bin/bash
syscall=$(ausyscall --dump | awk 'BEGIN{printf "syscall=\""}{if(NR!=1)printf $2" "}END{print "\""}')
sed  -i 's/syscall=.*/'"$syscall"'/' sysmonctl.cmp
