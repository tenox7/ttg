DESTDIR   ?=
PREFIX    ?= /usr/local
MANPREFIX ?= $(PREFIX)/man

CFLAGS += -Wall -Wextra
LDLIBS += -lnetsnmp

all: ttg

install: ttg 
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m755 ttg   $(DESTDIR)$(PREFIX)/bin

uninstall:
	rm -f $(PREFIX)$(PREFIX)/bin/ttg

clean:
	rm -f ttg

.PHONY: all clean install uninstall
