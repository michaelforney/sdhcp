# sdhcp version
VERSION   = 0.1

PREFIX    = /usr/local
DESTDIR   =
MANPREFIX = $(PREFIX)/share/man

CC        = cc
#CC       = musl-gcc
LD        = $(CC)
CPPFLAGS  = -D_BSD_SOURCE
CFLAGS    = -g -Wall -Wextra -O0 -ansi $(CPPFLAGS)
LDFLAGS   = -g
