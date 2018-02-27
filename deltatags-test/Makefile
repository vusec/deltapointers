.PHONY: all clean cleaner

ifndef TARGETDIR
    $(error TARGETDIR is undefined)
endif

OBJDIR       := $(TARGETDIR)/obj
OBJDIR_CPP   := $(TARGETDIR)/obj-cpp
BINDIR       := $(TARGETDIR)/bin

SRCS_C       := $(wildcard test_*.c)
SRCS_CPP     := $(wildcard test_*.cpp)
OBJS_C       := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS_C))
OBJS_CPP     := $(patsubst %.cpp,$(OBJDIR_CPP)/%.o,$(SRCS_CPP))
BINS         := $(patsubst %.c,$(BINDIR)/%,$(SRCS_C)) $(patsubst %.cpp,$(BINDIR)/%,$(SRCS_CPP))

LLVM_VERSION := 3.8.0
PKG_CONFIG   := python3 ../setup.py pkg-config
INCLUDES      = `$(PKG_CONFIG) llvm-passes-builtin-$(LLVM_VERSION) --target-cflags`

all: $(BINS)

$(BINDIR)/%: $(OBJDIR)/%.o | $(BINDIR)
	$(CC) $(LDFLAGS) -o $@ $^
$(BINDIR)/%: $(OBJDIR_CPP)/%.o | $(BINDIR)
	$(CXX) $(LDFLAGS) -o $@ $^

$(OBJDIR)/%.o: %.c | $(OBJDIR)
	$(CC) $(INCLUDES) $(CFLAGS) -O0 -c -o $@ $<
$(OBJDIR_CPP)/%.o: %.cpp | $(OBJDIR_CPP)
	$(CXX) $(INCLUDES) $(CXXFLAGS) -c -o $@ $<

.PRECIOUS: $(OBJS_C) $(OBJS_CPP)

clean:
	rm -f $(BINS) $(OBJS_C) $(OBJS_CPP)

cleaner: clean
	rm -rf prelink-* build* rts_* *.ll

.PHONY: bins
bins:
	@echo $(BINS)

$(OBJDIR) $(OBJDIR_CPP) $(BINDIR):
	mkdir -p $@
