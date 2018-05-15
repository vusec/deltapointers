import os.path
import infra
from infra.packages import LLVM, BuiltinLLVMPasses, LLVMPasses, LibShrink
from .packages import LibDeltaTags


class DeltaTags(infra.Instance):
    addrspace_bits = 32
    llvm_version = '3.8.0'
    llvm_patches = ['gold-plugins', 'statsfilter']
    debug = False # toggle for debug symbols

    rootdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    doxygen_flags = [
        #'-DLLVM_ENABLE_DOXYGEN=On',
        #'-DLLVM_DOXYGEN_SVG=On',
        #'-DLLVM_INSTALL_DOXYGEN_HTML_DIR=%s/build/doxygen' % rootdir
    ]
    llvm = LLVM(version=llvm_version, compiler_rt=False,
                patches=llvm_patches, build_flags=doxygen_flags)
    llvm_passes = LLVMPasses(llvm, rootdir + '/llvm-passes', 'deltatags',
                             use_builtins=True)
    libshrink = LibShrink(addrspace_bits, debug=debug)
    libdeltatags = LibDeltaTags(llvm_passes, addrspace_bits, overflow_bit=True,
                                runtime_stats=False, debug=debug)

    def __init__(self, name, overflow_check, optimizer):
        self.name = name
        self.overflow_check = overflow_check
        self.optimizer = optimizer

    def dependencies(self):
        yield self.llvm
        yield self.llvm_passes
        yield self.libshrink
        yield self.libdeltatags

    def configure(self, ctx):
        # helper libraries
        self.llvm.configure(ctx)
        self.llvm_passes.configure(ctx)
        self.libshrink.configure(ctx, static=True)
        self.libdeltatags.configure(ctx)

        if self.debug:
            ctx.cflags += ['-O0', '-ggdb']
            ctx.cxxflags += ['-O0', '-ggdb']
            LLVM.add_plugin_flags(ctx, '-disable-opt')
        else:
            # note: link-time optimizations break some programs (perlbench,
            # gcc) if our instrumentation runs and -O2 was not passed at
            # compile time
            ctx.cflags += ['-O2']
            ctx.cxxflags += ['-O2']

        def add_stats_pass(name, *args):
            LLVM.add_plugin_flags(ctx, name, '-stats-only=' + name, *args)

        # prepare initalizations of globals so that the next passes only have to
        # operate on instructions (rather than constantexprs)
        add_stats_pass('-defer-global-init')
        add_stats_pass('-expand-const-global-users')

        # make sure all calls to allocation functions are direct
        add_stats_pass('-replace-address-taken-malloc')

        # do some analysis for optimizations
        if self.optimizer == 'old':
            add_stats_pass('-safe-allocs-old')
        elif self.optimizer == 'new':
            # simplify loops to ease analysis
            LLVM.add_plugin_flags(ctx, '-loop-simplify')
            add_stats_pass('-safe-allocs')

        # find integers that contain pointer values and thus need to be masked
        add_stats_pass('-find-reinterpreted-pointers')

        # tag heap/stack/global allocations
        add_stats_pass('-deltatags-alloc',
                       '-address-space-bits=%d' % self.addrspace_bits)

        # propagate size tags on ptr arith and libc calls
        add_stats_pass('-deltatags-prop',
                       '-deltatags-check-overflow=' + self.overflow_check)

        # mask pointers at dereferences / libcalls
        add_stats_pass('-mask-pointers',
                       '-mask-pointers-ignore-list=strtok')

        # undo loop simplification changes
        if self.optimizer == 'new':
            LLVM.add_plugin_flags(ctx, '-simplifycfg')

        # dump IR for debugging
        LLVM.add_plugin_flags(ctx, '-dump-ir')

        # inline statically linked helpers
        LLVM.add_plugin_flags(ctx, '-custominline')

    def prepare_run(self, ctx):
        assert 'target_run_wrapper' not in ctx
        ctx.target_run_wrapper = self.libshrink.run_wrapper(ctx)

    @classmethod
    def make_instances(cls):
        # cls(name, overflow_check, optimizer)
        yield cls('deltatags-noopt', 'none', None)
        yield cls('deltatags', 'none', 'old')
        yield cls('deltatags-satarith', 'satarith', 'old')
        yield cls('deltatags-newopt', 'none', 'new')
