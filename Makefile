DESTDIR=
sdhcp: sdhcp.c debug.c
MANDIR = /usr/share/man

debug: sdhcp.c debug.c
	$(CC) -DDEBUG -o sdhcp sdhcp.c -static

all: sdhcp

install: all
	install -s sdhcp $(DESTDIR)/sbin
	gzip -c sdhcp.8 > $(DESTDIR)$(MANDIR)/man8/sdhcp.8.gz
	
clean:
	rm -f sdhcp ?*~
