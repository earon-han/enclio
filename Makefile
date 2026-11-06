CC ?= cc
CPPFLAGS += -Isrc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS += -Wl,-z,relro,-z,now
LDLIBS += -lseccomp
PREFIX ?= /usr/local
SOURCES = src/main.c src/internal.c src/seccomp.c src/proxy.c

.PHONY: all clean test unit install package
all: build/tegum
build/tegum: $(SOURCES) src/tegum.h src/proxy.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) $(LDFLAGS) $(LDLIBS) -o $@
test: all
	python3 tests/integration.py --binary $(CURDIR)/build/tegum
unit: build/proxy_unit
	build/proxy_unit
build/proxy_unit: tests/proxy_unit.c src/proxy.c src/proxy.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/proxy_unit.c src/proxy.c $(LDFLAGS) -o $@
install: all
	install -Dm755 build/tegum $(DESTDIR)$(PREFIX)/bin/tegum
package: all
	sh scripts/package.sh
clean:
	rm -rf build
