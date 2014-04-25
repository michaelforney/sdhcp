include config.mk

.POSIX:
.SUFFIXES: .c .o

HDR = util.h
LIB = \
	  util/strlcpy.o

SRC = sdhcp.c

OBJ = $(SRC:.c=.o) $(LIB)
BIN = $(SRC:.c=)
MAN = $(SRC:.c=.8)

all: options binlib

options:
	@echo sdhcp build options:
	@echo "CFLAGS   = ${CFLAGS}"
	@echo "LDFLAGS  = ${LDFLAGS}"
	@echo "CC       = ${CC}"

binlib: util.a
	$(MAKE) bin

bin: $(BIN)

$(OBJ): $(HDR) config.mk

.o:
	@echo LD $@
	@$(LD) -o $@ $< util.a $(LDFLAGS)

.c.o:
	@echo CC $<
	@$(CC) -c -o $@ $< $(CFLAGS)

util.a: $(LIB)
	@echo AR $@
	@$(AR) -r -c $@ $(LIB)
	@ranlib $@

install: all
	@echo installing executables to $(DESTDIR)$(PREFIX)/sbin
	@mkdir -p $(DESTDIR)$(PREFIX)/sbin
	@cp -f $(BIN) $(DESTDIR)$(PREFIX)/sbin
	@cd $(DESTDIR)$(PREFIX)/sbin && chmod 755 $(BIN)
	@echo installing manual pages to $(DESTDIR)$(MANPREFIX)/man8
	@mkdir -p $(DESTDIR)$(MANPREFIX)/man8
	@for m in $(MAN); do sed "s/VERSION/$(VERSION)/g" < "$$m" > $(DESTDIR)$(MANPREFIX)/man8/"$$m"; done
	@cd $(DESTDIR)$(MANPREFIX)/man8 && chmod 644 $(MAN)

uninstall:
	@echo removing executables from $(DESTDIR)$(PREFIX)/bin
	@cd $(DESTDIR)$(PREFIX)/bin && rm -f $(BIN)
	@echo removing manual pages from $(DESTDIR)$(MANPREFIX)/man8
	@cd $(DESTDIR)$(MANPREFIX)/man8 && rm -f $(MAN)

clean:
	@echo cleaning
	@rm -f $(BIN) $(OBJ)

.PHONY: all options clean install uninstall
