# on make install, install lock_dies and lock_dies.sh

all:
	make -C ../lock/

install:
	cp ../lock/bin/lock /usr/local/bin/lock_deis
	cp lock_deis.sh /etc/init.d/
	update-rc.d /etc/init.d/lock_deis.sh defaults
