from infra import Package
from infra.packages import ShrinkAddrSpace
from infra.util import run


class LibDeltaTags(Package):
    def __init__(self, addrspace_bits, overflow_bit):
        self.addrspace_bits = addrspace_bits
        self.overflow_bit = overflow_bit

    def dependencies(self):
        yield ShrinkAddrSpace(self.addrspace_bits, srcdir='shrinkaddrspace')

    def ident(self):
        return 'libdeltatags-%d%s' % (self.addrspace_bits,
                '-overflow-bit' if self.overflow_bit else '')

    def fetch(self, ctx):
        raise NotImplementedError

    def build(self, ctx):
        raise NotImplementedError

    def install(self, ctx):
        raise NotImplementedError

    def is_fetched(self, ctx):
        raise NotImplementedError

    def is_built(self, ctx):
        raise NotImplementedError

    def is_installed(self, ctx):
        raise NotImplementedError
