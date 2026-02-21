PREFIX ?= /usr/local
DESTDIR ?= $(PREFIX)

all:
	cargo build --release

install:
	install -Dm755 target/release/sdme $(DESTDIR)/bin/sdme

uninstall:
	rm -f $(DESTDIR)/bin/sdme

clean:
	cargo clean

.PHONY: all install uninstall clean
