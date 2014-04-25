# sdhcp version
VERSION   = 0.1

PREFIX    = /usr/local
DESTDIR   =
MANPREFIX = $(PREFIX)/share/man

#CC       = gcc
#CC       = musl-gcc
LD        = $(CC)
CPPFLAGS  = -D_BSD_SOURCE
CFLAGS    = -g -Wall -ansi $(CPPFLAGS)
LDFLAGS   = -g
