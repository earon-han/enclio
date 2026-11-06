CC ?= cc
CPPFLAGS += -Isrc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS += -Wl,-z,relro,-z,now
LDLIBS += -lseccomp
PREFIX ?= /usr/local
SOURCES = src/main.c src/internal.c src/seccomp.c src/proxy.c src/resources.c src/guardian.c src/output.c

.PHONY: all clean test unit install package
all: build/enclio
build/enclio: $(SOURCES) src/enclio.h src/proxy.h src/resources.h src/guardian.h src/output.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) $(LDFLAGS) $(LDLIBS) -o $@
test: all
	python3 tests/integration.py --binary $(CURDIR)/build/enclio
unit: build/proxy_unit build/resource_unit build/transport_filter_unit build/listener_handoff_unit build/seccomp_rules_unit
	build/proxy_unit
	build/resource_unit
	build/transport_filter_unit
	build/listener_handoff_unit
	build/seccomp_rules_unit
build/proxy_unit: tests/proxy_unit.c src/proxy.c src/proxy.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/proxy_unit.c src/proxy.c $(LDFLAGS) $(LDLIBS) -o $@
install: all
	install -Dm755 build/enclio $(DESTDIR)$(PREFIX)/bin/enclio
package: all
	sh scripts/package.sh
clean:
	rm -rf build

build/resource_unit: tests/resource_unit.c src/resources.c src/resources.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/resource_unit.c src/resources.c $(LDFLAGS) -o $@
build/transport_filter_unit: tests/transport_filter_unit.c src/proxy.c src/proxy.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/transport_filter_unit.c $(LDFLAGS) $(LDLIBS) -o $@
build/proxy_fuzz: tests/proxy_fuzz.c src/proxy.c src/proxy.h
	mkdir -p build
	$(CC) $(CPPFLAGS) -DENCLIO_PROXY_TESTING -std=c11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined src/proxy.c tests/proxy_fuzz.c $(LDLIBS) -o $@
.PHONY: fuzz-smoke network-test
fuzz-smoke: build/proxy_fuzz
	build/proxy_fuzz 250000
network-test:
	python3 tests/network_integration.py --output build/network-integration.json

build/listener_handoff_unit: tests/listener_handoff_unit.c src/proxy.c src/proxy.h src/enclio.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/listener_handoff_unit.c $(LDFLAGS) $(LDLIBS) -o $@

build/seccomp_rules_unit: tests/seccomp_rules_unit.c src/seccomp.c src/enclio.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/seccomp_rules_unit.c src/seccomp.c $(LDFLAGS) $(LDLIBS) -o $@
