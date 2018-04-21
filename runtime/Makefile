# local build config for debugging (overwritten in deps.py)
OBJDIR         ?= ./obj
LLVM_VERSION   ?= 3.8.0
ADDRSPACE_BITS ?= 32
RUNTIME_STATS  ?= false
OVERFLOW_BIT   ?= false
DEBUG          ?= false

#PATHCLANGINCLUDE ?= ../build/packages/llvm-3.8.0/install/lib/clang/3.8.0/include
PKG_CONFIG       := python3 ../setup.py pkg-config
LLVM_PREFIX      := `$(PKG_CONFIG) llvm-$(LLVM_VERSION) --prefix`
PATHCLANGINCLUDE := $(LLVM_PREFIX)/lib/clang/$(LLVM_VERSION)/include
BUILTIN_CFLAGS   := `$(PKG_CONFIG) llvm-passes-builtin-$(LLVM_VERSION) --runtime-cflags`

CC     := $(LLVM_PREFIX)/bin/clang
CFLAGS := -flto -fpic -Wall -Wextra -march=native -I$(PATHCLANGINCLUDE) \
          -DADDRSPACE_BITS=$(ADDRSPACE_BITS) $(BUILTIN_CFLAGS)
ifeq ($(OVERFLOW_BIT), true)
	CFLAGS += -DOVERFLOW_BIT
endif
ifeq ($(RUNTIME_STATS), true)
	CFLAGS += -DRUNTIME_STATS
endif
ifeq ($(DEBUG), true)
	CFLAGS += -DDEBUG
endif

LIB  := libdeltatags.a
OBJS := libptrret mask debug runtimestats mask-wrappers
OBJS := $(patsubst %,$(OBJDIR)/%.o,$(OBJS))

.PHONY: all clean

all: $(OBJDIR)/$(LIB)

$(OBJDIR)/$(LIB): $(OBJS)
	ar rcs $@ $^

$(OBJDIR)/%.o: %.c addrspace.h | $(OBJDIR)
	$(CC) -c $(CFLAGS) -o $@ $<

$(OBJDIR):
	mkdir -p $@

clean:
	rm -rf $(OBJDIR)
