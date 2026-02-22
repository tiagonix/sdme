PREFIX ?= /usr/local
DESTDIR ?= $(PREFIX)

all:
	cargo build --release

install: install-man
	install -Dm755 target/release/sdme $(DESTDIR)/bin/sdme

install-man:
	install -Dm644 docs/sdme.1 $(DESTDIR)/share/man/man1/sdme.1

uninstall: uninstall-man
	rm -f $(DESTDIR)/bin/sdme

uninstall-man:
	rm -f $(DESTDIR)/share/man/man1/sdme.1

clean:
	cargo clean

.PHONY: all install install-man uninstall uninstall-man clean
