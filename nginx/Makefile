PWD = $(shell pwd)

start:
	nginx -c nginx.conf -e $(PWD)/nginx-error.log -p $(PWD)

stop:
	nginx -c nginx.conf -e $(PWD)/nginx-error.log -p $(PWD) -s stop

reload:
	nginx -c nginx.conf -e $(PWD)/nginx-error.log -p $(PWD) -s reload

restart:
	nginx -c nginx.conf -e $(PWD)/nginx-error.log -p $(PWD) -s stop
	sleep 1
	nginx -c nginx.conf -e $(PWD)/nginx-error.log -p $(PWD) -s start

check:
	nginx -c nginx.conf -e $(PWD)/nginx-error.log -p $(PWD) -t
