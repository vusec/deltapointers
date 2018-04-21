import os
from infra import Package
from infra.packages import ShrinkAddrSpace
from infra.util import run
from infra.instances.helpers.llvm_lto import add_lto_args


def strbool(b):
    return 'true' if b else 'false'


class LibDeltaTags(Package):
    def __init__(self, llvm_passes, addrspace_bits, overflow_bit,
                 runtime_stats=False, debug=False):
        self.llvm_passes = llvm_passes
        self.addrspace_bits = addrspace_bits
        self.overflow_bit = overflow_bit
        self.runtime_stats = runtime_stats
        self.debug = debug

    def dependencies(self):
        yield self.llvm_passes.llvm
        curdir = os.path.dirname(os.path.abspath(__file__))
        yield ShrinkAddrSpace(self.addrspace_bits,
                              srcdir=curdir + '/shrinkaddrspace')

    def ident(self):
        return 'libdeltatags-%d%s' % (self.addrspace_bits,
                '-overflow-bit' if self.overflow_bit else '')

    def fetch(self, ctx):
        os.symlink(os.path.join(ctx.paths.root, 'runtime'), 'src')

    def build(self, ctx):
        os.makedirs('obj', exist_ok=True)
        self.run_make(ctx, '-j%d' % ctx.jobs)

    def install(self, ctx):
        pass

    def run_make(self, ctx, *args):
        os.chdir(self.path(ctx, 'src'))
        env = {
            'OBJDIR': self.path(ctx, 'obj'),
            'LLVM_VERSION': self.llvm_passes.llvm.version,
            'ADDRSPACE_BITS': str(self.addrspace_bits),
            'OVERFLOW_BIT': strbool(self.overflow_bit),
            'RUNTIME_STATS': strbool(self.runtime_stats),
            'DEBUG': strbool(self.debug)
        }
        return run(ctx, ['make', *args], env=env)

    def is_fetched(self, ctx):
        return os.path.exists('src')

    def is_built(self, ctx):
        return os.path.exists('obj/libdeltatags.a')

    def is_installed(self, ctx):
        return self.is_built(ctx)

    def configure(self, ctx):
        # undef symbols to make sure the pass can find them
        exposed_functions = [
            'strsize_nullsafe', 'strtok', 'strtok_ubound', 'rts_gep',
            'rts_load', 'rts_store', 'check_neg_arith', 'mask_pointer_bzhi',
            'mask_pointer_pext_reg', 'mask_pointer_pext_glob', 'execv_mask',
            'execvp_mask', 'execvpe_mask', 'execve_mask', 'writev_mask',
            'is_oob', '_tag_pointer', '_mask_pointer', '_tag_of', '_take_tag',
            '_ptr_arith'
        ]
        ctx.ldflags += ['-u__noinstrument_' + fn for fn in exposed_functions]

        # link static library
        ctx.ldflags += ['-L' + self.path(ctx, 'obj'), '-Wl,-whole-archive',
                        '-l:libdeltatags.a', '-Wl,-no-whole-archive']
        ctx.cflags += ['-DDELTAPOINTERS', '-I' + self.path(ctx, 'src')]
        ctx.cflags += self.llvm_passes.runtime_cflags(ctx)

        # pass overflow-bit option to instrumentation pass
        add_lto_args(ctx, '-overflow-bit=' + strbool(self.overflow_bit))
