DESTDIR=
MANDIR = /usr/share/man

sdhcp: sdhcp.c
	$(CC) -O2 -o $@ sdhcp.c -static -Wall -ansi

debug: sdhcp.c debug.c
	$(CC) -DDEBUG -o sdhcp sdhcp.c -static -O0 -g -Wall -ansi

all: sdhcp

install: all
	install -s sdhcp $(DESTDIR)/sbin
	gzip -c sdhcp.8 > $(DESTDIR)$(MANDIR)/man8/sdhcp.8.gz
	
clean:
	rm -f sdhcp ?*~
