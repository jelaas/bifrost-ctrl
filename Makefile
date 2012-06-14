CC=gcc
CFLAGS=-Wall -Os -g -march=i586
#LDFLAGS=-static
LDLIBS=-lssh -lcrypto -ldl -lz -lrt -static
all:	bifrost-ctrl
bifrost-ctrl:	bifrost-ctrl.o des.o md5_crypt.o md5.o daemonize.o
install:	bifrost-ctrl
	strip bifrost-ctrl
	mkdir -p $(DESTDIR)/sbin
	cp -p bifrost-ctrl $(DESTDIR)/sbin
clean:	
	rm -f *.o bifrost-ctrl
