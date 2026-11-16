# polibtls -- an Oberon-2 binding to libtls (LibreTLS) for poc, the
# Peaseblossom Oberon Compiler. See AGENTS.md; adapted from polibfyaml's
# and posockets' GNUmakefiles.
#
# The library polibtls is built in $(LIBDIR), with each module's C part
# (src/<Module>.c beside src/<Module>.Mod) compiled and archived with it,
# and with libtls's compile flags (-c-flag) and link flags (-link)
# recorded in it, so a program using polibtls passes none. The tests and
# examples take the library from there, so they test this checkout and
# what make install would install.
#
# poc writes each module's .sym, .ll and .o, and the programs, into $(BUILD).
# Every program writes the files of the modules it compiles into the same
# $(BUILD), so make must not build two at once.
#
# The tests' certificates and keys are made by test/make-certs.sh into
# $(CERTS), never committed.
#
# make install installs the library in $(POCLIBDIR), ~/.local/lib/poc by
# default, with and without debug information, under -OC, the only size
# model the library supports. poc puts each in <triple>/<variant>/ there.

POC      ?= poc
PREFIX ?= $(HOME)/.local
POCLIBDIR ?= $(PREFIX)/lib/poc
# The size model: decided in PLAN.md, "Integer model"; never mix models.
POCFLAGS := -OC
MODELS := OC
VARIANTS := $(MODELS) $(addsuffix -g,$(MODELS))
# --track-fds=yes makes valgrind list the descriptors open at exit; the
# valgrind target requires that the test opened none of them. 60 callers
# let vg-reachable.sh see whether a block was allocated within tls_init.
VALGRIND ?= valgrind --num-callers=60 --leak-check=full --show-leak-kinds=all --track-fds=yes --error-exitcode=99 --suppressions=poc-gc.supp
# memcheck can't follow poc's coroutines (posockets' finding, PLAN.md,
# "Testing"), so the tests in TASKTESTS run with no memory check, only
# the descriptor check, by vg-fds.sh: no --error-exitcode, since valgrind
# 3.27.1 counts every descriptor open at exit as an error, Tasks'
# self-pipe included.
VALGRIND_TASKS ?= valgrind --tool=none --track-fds=yes

# An installed library on POC_LIBRARY_PATH would be taken in place of this
# checkout's source, or would stop the build if another poc wrote it.
unexport POC_LIBRARY_PATH

BUILD := build
LIBDIR := $(BUILD)/lib
CERTS := $(BUILD)/certs

LIBRARY := polibtls
# The library's modules, in import order (PLAN.md, "Modules").
LIBMODS := TlsThin Tls

# libtls's flags, from pkg-config (LibreTLS 3.8.1: none and -ltls).
TLS_CFLAGS := $(shell pkg-config --cflags libtls)
TLS_LIBS := $(shell pkg-config --libs libtls)
LINK := $(foreach f,$(TLS_CFLAGS),-c-flag $(f)) $(foreach f,$(TLS_LIBS),-link $(f))

# $(call variant-flags,<variant>) gives poc's flags for a variant: OC-g gives
# -OC -g.
variant-flags = -$(firstword $(subst -, ,$(1))) $(if $(filter %-g,$(1)),-g)

# A library records the poc that built it, and another poc refuses it, so
# each library depends on poc itself.
POCBIN := $(shell command -v $(POC))

# The modules and their C parts, whichever have one.
LIBSRC := $(LIBMODS:%=src/%.Mod) $(wildcard $(LIBMODS:%=src/%.c))
# Test programs (test/<name>.Mod, each a main module), run from test/.
TESTS := TestInit TestThin TestConfig TestBlocking
# tests that run tasks (VALGRIND_TASKS)
TASKTESTS :=
# Programs that must halt (test/<name>.Mod), as name:Assert-code. poc's
# ASSERT(x, n) prints "assertion failed (n)" on standard error and exits
# with status 10, so `make test` requires both.
HALTTESTS := HaltConfigClosed:91 HaltContextClosed:91 HaltConnectionClosed:91 \
  HaltRange:93 HaltContextOpen:94 HaltNegativeFd:95
ASSERTSTATUS := 10

# Example programs (examples/<name>.Mod), as name:required-exit-status.
# `make test` runs each from examples/ and requires that status and
# stdout identical to examples/<name>.expected. None until Phase 8.
EXAMPLES :=

TESTBINS := $(TESTS:%=$(BUILD)/%)
HALTBINS := $(foreach h,$(HALTTESTS),$(BUILD)/$(firstword $(subst :, ,$(h))))
EXAMPLEBINS := $(foreach e,$(EXAMPLES),$(BUILD)/$(firstword $(subst :, ,$(e))))

.PHONY: all tests certs test valgrind clean install uninstall
.NOTPARALLEL:

all: tests

tests: $(TESTBINS) $(HALTBINS) $(EXAMPLEBINS) certs

$(BUILD):
	mkdir -p $@

certs: $(CERTS)/.stamp

# Made once per build directory; make clean removes them with it.
$(CERTS)/.stamp: test/make-certs.sh | $(BUILD)
	rm -rf $(CERTS)
	test/make-certs.sh $(CERTS)
	touch $@

$(LIBDIR)/$(LIBRARY)-%.stamp: $(LIBSRC) $(POCBIN) | $(BUILD)
	mkdir -p $(LIBDIR)
	cd src && $(POC) $(call variant-flags,$*) -output-dir $(abspath $(LIBDIR)) \
	  $(LINK) -library $(LIBRARY) $(LIBMODS:%=%.Mod)
	touch $@

$(BUILD)/Test%: test/Test%.Mod test/Check.Mod test/TestPeers.Mod test/TestPeers.c $(LIBDIR)/$(LIBRARY)-OC.stamp | $(BUILD)
	$(POC) $(POCFLAGS) -library-path $(LIBDIR) -import-path test -output-dir $(BUILD) -o $@ $<

$(BUILD)/Halt%: test/Halt%.Mod $(LIBDIR)/$(LIBRARY)-OC.stamp | $(BUILD)
	$(POC) $(POCFLAGS) -library-path $(LIBDIR) -output-dir $(BUILD) -o $@ $<

$(BUILD)/Example%: examples/Example%.Mod $(LIBDIR)/$(LIBRARY)-OC.stamp | $(BUILD)
	$(POC) $(POCFLAGS) -library-path $(LIBDIR) -output-dir $(BUILD) -o $@ $<

# Run every test from test/; report all, fail at the end if any failed.
# Each halt test must exit with poc's ASSERT status and name its Assert
# code on standard error. Standard input is /dev/null.
test: tests
	@status=0; for t in $(TESTS); do \
	  echo "== $$t"; (cd test && ../$(BUILD)/$$t < /dev/null) || status=1; \
	done; \
	for h in $(HALTTESTS); do \
	  t=$${h%%:*}; code=$${h##*:}; echo "== $$t (must fail ASSERT code $$code)"; \
	  (cd test && ../$(BUILD)/$$t < /dev/null) 2> $(BUILD)/$$t.err; got=$$?; \
	  if [ $$got -eq $(ASSERTSTATUS) ] && grep -q "assertion failed ($$code)" $(BUILD)/$$t.err; then \
	    echo "ok   - $$t: $$(cat $(BUILD)/$$t.err)"; \
	  else echo "FAIL - $$t exited with $$got: $$(cat $(BUILD)/$$t.err)"; status=1; fi; \
	done; \
	for x in $(EXAMPLES); do \
	  e=$${x%%:*}; want=$${x##*:}; \
	  echo "== $$e (must exit $$want with examples/$$e.expected)"; \
	  (cd examples && ../$(BUILD)/$$e < /dev/null) > $(BUILD)/$$e.out; got=$$?; \
	  if [ $$got -eq $$want ] && cmp -s $(BUILD)/$$e.out examples/$$e.expected; then echo "ok   - $$e"; \
	  else echo "FAIL - $$e: exit $$got, output:"; diff examples/$$e.expected $(BUILD)/$$e.out; status=1; fi; \
	done; exit $$status

# Each test under valgrind. Besides definite and indirect leaks, every
# still-reachable block must be the collector's own or OpenSSL's fixed
# global state (test/vg-reachable.sh), and every descriptor open at exit
# must be one the test inherited (test/vg-fds.sh, from valgrind's
# --track-fds=yes report). A test in TASKTESTS gets the descriptor check
# only (VALGRIND_TASKS).
valgrind: tests
	@status=0; for t in $(TESTS); do \
	  case " $(TASKTESTS) " in \
	  *" $$t "*) \
	    echo "== valgrind $$t (descriptors only: memcheck can't follow poc's coroutines)"; \
	    (cd test && $(VALGRIND_TASKS) --log-file=../$(BUILD)/$$t.vg ../$(BUILD)/$$t < /dev/null) || status=1; \
	    grep -E 'FILE DESCRIPTORS' $(BUILD)/$$t.vg;; \
	  *) \
	    echo "== valgrind $$t"; \
	    (cd test && $(VALGRIND) --log-file=../$(BUILD)/$$t.vg ../$(BUILD)/$$t < /dev/null) || status=1; \
	    grep -E 'ERROR SUMMARY|lost:|reachable:|FILE DESCRIPTORS' $(BUILD)/$$t.vg; \
	    test/vg-reachable.sh $(BUILD)/$$t.vg || { echo "FAIL - $$t: still-reachable memory neither the collector's nor OpenSSL's"; status=1; };; \
	  esac; \
	  test/vg-fds.sh $(BUILD)/$$t.vg || { echo "FAIL - $$t: descriptors left open at exit (see $(BUILD)/$$t.vg)"; status=1; }; \
	done; exit $$status

# install copies the library, in each variant, into $(POCLIBDIR) with poc
# -install-library, which copies only what a program needs: the archive
# (the C parts' objects are in it), the shared object, the manifest, and
# each module's .sym and .owner. A program then finds it with -library-path
# $(POCLIBDIR). A library records the poc that built it, and another poc
# refuses it: install again after upgrading poc.
define newline


endef

install: $(foreach v,$(VARIANTS),$(LIBDIR)/$(LIBRARY)-$(v).stamp)
	$(foreach v,$(VARIANTS),$(POC) $(call variant-flags,$(v)) \
	  -library-path $(LIBDIR) -install-library $(LIBRARY) -output-dir $(POCLIBDIR)$(newline))

# uninstall removes from $(POCLIBDIR)/<triple>/<variant> what install put
# there. It leaves other libraries' files alone, and removes a directory only
# when nothing is left in it. The triple is poc's target.
INSTALLED_FILES := $(LIBRARY).library lib$(LIBRARY).a lib$(LIBRARY).so lib$(LIBRARY).so.0.0 \
  $(foreach m,$(LIBMODS),$(m).sym $(m).owner)

uninstall:
	@triple=$$($(POC) -version | sed -n 's/^target \([^ ]*\).*/\1/p'); \
	if [ -z "$$triple" ]; then echo "uninstall: cannot get the target from $(POC) -version" >&2; exit 1; fi; \
	for v in $(VARIANTS); do \
	  dir=$(POCLIBDIR)/$$triple/$$v; \
	  if [ -d "$$dir" ]; then \
	    echo "cd $$dir && rm -f $(INSTALLED_FILES)"; \
	    (cd "$$dir" && rm -f $(INSTALLED_FILES)) || exit 1; \
	    rmdir "$$dir" 2>/dev/null || :; \
	  fi; \
	done; \
	rmdir $(POCLIBDIR)/$$triple 2>/dev/null || :; \
	rmdir $(POCLIBDIR) 2>/dev/null || :

clean:
	rm -rf $(BUILD)
