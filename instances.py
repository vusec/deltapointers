import os.path
import infra
from infra.packages import LLVM, BuiltinLLVMPasses, LLVMPasses, ShrinkAddrSpace
from infra.instances.helpers.llvm_lto import add_lto_args, add_stats_pass
#from infra.packages.llvm.helpers import add_lto_args, add_stats_pass
from deps import LibDeltaTags


class DeltaTags(infra.Instance):
    addrspace_bits = 32
    llvm_version = '3.8.0'
    llvm_patches = ['gold-plugins', 'statsfilter']

    curdir = os.path.dirname(os.path.abspath(__file__))
    doxygen_flags = [
        #'-DLLVM_ENABLE_DOXYGEN=On',
        #'-DLLVM_DOXYGEN_SVG=On',
        #'-DLLVM_INSTALL_DOXYGEN_HTML_DIR=%s/build/doxygen' % curdir
    ]
    llvm = LLVM(version=llvm_version, compiler_rt=False,
                patches=llvm_patches, build_flags=doxygen_flags)
    llvm_passes = LLVMPasses(llvm, curdir + '/llvm-passes', 'deltatags',
                             use_builtins=True)
    shrinkaddrspace = ShrinkAddrSpace(addrspace_bits,
                                      srcdir=curdir + '/shrinkaddrspace')
    libdeltatags = LibDeltaTags(llvm_passes, addrspace_bits, overflow_bit=True,
                                runtime_stats=False, debug=False)

    def __init__(self, name, overflow_check, optimizer):
        self.name = name
        self.overflow_check = overflow_check
        self.optimizer = optimizer

    def dependencies(self):
        yield self.llvm
        yield self.llvm_passes
        yield self.shrinkaddrspace
        yield self.libdeltatags

    def configure(self, ctx):
        # helper libraries
        self.llvm.configure(ctx, lto=True)
        self.llvm_passes.configure(ctx)
        self.shrinkaddrspace.configure(ctx, static=True)
        self.libdeltatags.configure(ctx)

        # prepare initalizations of globals so that the next passes only have to
        # operate on instructions (rather than constantexprs)
        add_stats_pass(ctx, '-defer-global-init')
        add_stats_pass(ctx, '-expand-const-global-users')

        # make sure all calls to allocation functions are direct
        add_stats_pass(ctx, '-replace-address-taken-malloc')

        # do some analysis for optimizations
        if self.optimizer == 'old':
            add_stats_pass(ctx, '-safe-allocs-old')
        elif self.optimizer == 'new':
            # simplify loops to ease analysis
            add_lto_args(ctx, '-loop-simplify')
            add_stats_pass(ctx, '-safe-allocs')

        # find integers that contain pointer values and thus need to be masked
        add_stats_pass(ctx, '-find-reinterpreted-pointers')

        # tag heap/stack/global allocations
        add_stats_pass(ctx, '-size-tag-alloc',
                            '-address-space-bits', self.addrspace_bits)

        # propagate size tags on ptr arith and libc calls
        add_stats_pass(ctx, '-size-tag-prop',
                '-check-ptr-arith-overflow=' + self.overflow_check)

        # mask pointers at dereferences / libcalls
        add_stats_pass(ctx, '-mask-pointers',
                '-mask-pointers-ignore-list=strtok')

        # undo loop simplification changes
        if self.optimizer == 'new':
            add_lto_args(ctx, '-simplifycfg')

        # dump IR for debugging
        add_lto_args(ctx, '-dump-ir')

        # inline statically linked helpers
        add_lto_args(ctx, '-custominline')

    @classmethod
    def make_instances(cls):
        # cls(name, overflow_check, optimizer)
        yield cls('deltatags', 'none', None)
        yield cls('deltatags-opt', 'none', 'old')
        yield cls('deltatags-corrupt', 'corrupt', None)
        yield cls('deltatags-corrupt-opt', 'corrupt', 'old')
        yield cls('deltatags-newopt', 'none', 'new')
