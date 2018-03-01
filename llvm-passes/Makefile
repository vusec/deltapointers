LLVM_VERSION = 3.8.0
CXX          = g++
PKG_CONFIG   = python3 ../setup.py pkg-config
LLVM_PREFIX  = $(shell $(PKG_CONFIG) llvm-$(LLVM_VERSION) --prefix)
LLVM_CONFIG  = $(LLVM_PREFIX)/bin/llvm-config
OBJDIR       = $(shell $(PKG_CONFIG) llvm-passes-deltatags --objdir)
PREFIX       = $(shell $(PKG_CONFIG) llvm-passes-deltatags --prefix)
CFLAGS       = -Werror -Wall -std=c++0x -g -O2 -I. \
               $(shell $(PKG_CONFIG) llvm-passes-builtin-$(LLVM_VERSION) --cxxflags) \
               $(shell $(LLVM_CONFIG) --cxxflags | sed s/-I/-isystem/g)
LDFLAGS      = -g -shared \
               $(shell $(PKG_CONFIG) llvm-passes-builtin-$(LLVM_VERSION) --ldflags) \
               -Wl,--no-undefined -L$(LLVM_PREFIX)/lib -l:LLVMgold.so -Wl,--rpath=$(LLVM_PREFIX)/lib

SRCS     := $(wildcard *.cpp)
OBJNAMES := $(patsubst %.cpp,%.o,$(SRCS))
OBJS     := $(addprefix $(OBJDIR)/,$(OBJNAMES))
DEPS     := $(OBJS:.o=.d)
LIB      := libpasses.so

all: $(OBJDIR)/$(LIB)

$(OBJDIR)/$(LIB): $(OBJS)
	cd $(OBJDIR) && $(CXX) $(OBJNAMES) $(LDFLAGS) -o $(@F)

-include $(DEPS)

$(OBJDIR)/%.o: %.cpp | $(OBJDIR)
	$(CXX) -c $(CFLAGS) -MMD -o $@ $<

$(OBJDIR):
	mkdir -p $@

clean:
	rm -rf $(OBJDIR)

install: $(PREFIX)/$(LIB)

$(PREFIX)/%: $(OBJDIR)/% | $(PREFIX)
	cp $< $@

uninstall:
	rm -f $(PREFIX)/$(LIB)

$(PREFIX):
	mkdir -p $@
