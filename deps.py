import infra
from infra.packages import ShrinkAddrSpace


class LibDeltaTags(infra.Package):
    def __init__(self, addrspace_bits, overflow_bit):
        self.addrspace_bits = addrspace_bits
        self.overflow_bit = overflow_bit

    def dependencies(self):
        yield ShrinkAddrSpace(self.addrspace_bits, srcdir='shrinkaddrspace')

    def ident(self):
        return 'libdeltatags-%d%s' % (self.addrspace_bits,
                '-overflow-bit' if self.overflow_bit else '')
