LLVM_VERSION   = 3.8.0
CXX            = g++
PKG_CONFIG     = python3 ../setup.py pkg-config
LLVM_PREFIX    = $(shell $(PKG_CONFIG) llvm-$(LLVM_VERSION) --prefix)
LLVM_CONFIG    = $(LLVM_PREFIX)/bin/llvm-config
OBJDIR         = $(shell $(PKG_CONFIG) llvm-passes-deltatags --objdir)
PREFIX         = $(shell $(PKG_CONFIG) llvm-passes-deltatags --prefix)
CFLAGS         = -Werror -Wall -std=c++0x -g -O2 -I. \
                 $(shell $(PKG_CONFIG) llvm-passes-builtin-$(LLVM_VERSION) --cxxflags) \
                 $(shell $(LLVM_CONFIG) --cxxflags | sed s/-I/-isystem/g)
BUILTIN_PREFIX = $(shell $(PKG_CONFIG) llvm-passes-builtin-$(LLVM_VERSION) --prefix)
LDFLAGS        = -g -shared -Wl,--no-undefined \
                 -L$(LLVM_PREFIX)/lib -l:LLVMgold.so -Wl,--rpath=$(LLVM_PREFIX)/lib \
                 -L$(BUILTIN_PREFIX) -Wl,-whole-archive -lpasses-builtin -Wl,-no-whole-archive
LDFLAGSOPT     = -g -shared  \
                 -L$(BUILTIN_PREFIX) -Wl,-whole-archive -lpasses-builtin -Wl,-no-whole-archive

SRCS     := $(wildcard *.cpp)
OBJNAMES := $(patsubst %.cpp,%.o,$(SRCS))
OBJS     := $(addprefix $(OBJDIR)/,$(OBJNAMES))
DEPS     := $(OBJS:.o=.d)
LIB      := libpasses.so
LIBOPT   := libpasses-opt.so

all: $(OBJDIR)/$(LIB) $(OBJDIR)/$(LIBOPT)

$(OBJDIR)/$(LIB): $(OBJS) $(BUILTIN_PREFIX)/libpasses-builtin.a
	cd $(OBJDIR) && $(CXX) $(OBJNAMES) $(LDFLAGS) -o $(@F)

$(OBJDIR)/$(LIBOPT): $(OBJS) $(BUILTIN_PREFIX)/libpasses-builtin.a
	cd $(OBJDIR) && $(CXX) $(OBJNAMES) $(LDFLAGSOPT) -o $(@F)

-include $(DEPS)

$(OBJDIR)/%.o: %.cpp | $(OBJDIR)
	$(CXX) -c $(CFLAGS) -MMD -o $@ $<

$(OBJDIR):
	mkdir -p $@

clean:
	rm -rf $(OBJDIR)

install: $(PREFIX)/$(LIB) $(PREFIX)/$(LIBOPT)

$(PREFIX)/%: $(OBJDIR)/% | $(PREFIX)
	cp $< $@

uninstall:
	rm -f $(PREFIX)/$(LIB)

$(PREFIX):
	mkdir -p $@
