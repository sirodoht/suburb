PWD = $(shell pwd)

start:
	nginx -c nginx.conf -e $(PWD)/nginx-error.log -p $(PWD)

stop:
	nginx -c nginx.conf -e $(PWD)/nginx-error.log -p $(PWD) -s stop

reload:
	nginx -c nginx.conf -e $(PWD)/nginx-error.log -p $(PWD) -s reload

check:
	nginx -c nginx.conf -e $(PWD)/nginx-error.log -p $(PWD) -t
