import infra
from infra.packages import LLVM, ShrinkAddrSpace
from infra.instances.helpers.llvm_lto import add_lto_args, add_stats_pass
#from infra.packages.llvm.helpers import add_lto_args, add_stats_pass
from deps import LibDeltaTags


class DeltaTags(infra.Instance):
    addrspace_bits = 32
    llvm_version = '3.8.0'
    llvm_patches = ['gold-plugins', 'statsfilter', 'aarch64-bugfix']

    llvm = LLVM(version=llvm_version, compiler_rt=False, patches=llvm_patches)
                #build_flags=['-DLLVM_ENABLE_DOXYGEN=On'])
    shrinkaddrspace = ShrinkAddrSpace(addrspace_bits, srcdir='shrinkaddrspace')
    libdeltatags = LibDeltaTags(addrspace_bits, overflow_bit=True)

    def __init__(self, name, overflow_check, optimize):
        self.name = name
        self.overflow_check = overflow_check
        self.optimize = optimize

    def dependencies(self):
        return [self.llvm, self.shrinkaddrspace, self.libdeltatags]

    def configure(self, ctx):
        # helper libraries
        self.llvm.configure(ctx, lto=True)
        self.shrinkaddrspace.configure(ctx, static=True)
        self.libdeltatags.configure(ctx)

        # prepare initalizations of globals so that the next passes only have to
        # operate on instructions (rather than constantexprs)
        add_stats_pass(ctx, '-defer-global-init')
        add_stats_pass(ctx, '-expand-const-global-users')

        # make sure all calls to allocation functions are direct
        add_stats_pass(ctx, '-replace-address-taken-malloc')

        # do some analysis for optimizations
        if self.optimize == 'old':
            add_stats_pass(ctx, '-safe-allocs-old')
        elif self.optimize == 'new':
            # simplify loops to ease analysis
            add_lto_args(ctx, '-loop-simplify')
            add_stats_pass(ctx, '-safe-allocs')

        # find integers that contain pointer values and thus need to be masked
        add_stats_pass(ctx, '-find-reinterpreted-pointers')

        # tag heap/stack/global allocations
        add_stats_pass(ctx, '-size-tag-alloc')

        # propagate size tags on ptr arith and libc calls
        add_stats_pass(ctx, '-size-tag-prop',
                '-check-ptr-arith-overflow=' + self.overflow_check)

        # mask pointers at dereferences / libcalls
        add_stats_pass(ctx, '-mask-pointers',
                '-mask-pointers-ignore-list=strtok')

        # undo loop simplification changes
        if self.optimize == 'new':
            add_lto_args(ctx, '-simplifycfg')

        # dump IR for debugging
        add_lto_args(ctx, '-dump-ir')

        # inline statically linked helpers
        add_lto_args(ctx, '-custominline')

    @classmethod
    def make_instances(cls):
        yield cls('deltatags', 'none', None)
        yield cls('deltatags-opt', 'none', 'old')
        yield cls('deltatags-corrupt', 'corrupt', None)
        yield cls('deltatags-corrupt-opt', 'corrupt', 'old')
        yield cls('deltatags-newopt', 'none', 'new')
