#include "AddressSpace.h"

using namespace llvm;

cl::opt<unsigned> AddressSpaceBits("address-space-bits",
        cl::desc("Number of possible (lower) non-zero bits in a pointer (used for pointer masking)"),
        cl::init(64));

cl::opt<unsigned> PointerBits("pointer-bits",
        cl::desc("Total number of bits in a pointer (architectural)"),
        cl::init(64));

cl::opt<bool> OverflowBit("overflow-bit",
        cl::desc("Reserve most significant pointer bit for overflow on pointer arithmetic (implies 64-bit masking)"),
        cl::init(false));

unsigned long long getAddressSpaceMask(bool MayPreserveOverflowBit) {
    unsigned long long Mask = (unsigned long long)(-1LL) >> (PointerBits - AddressSpaceBits);
    if (OverflowBit && MayPreserveOverflowBit)
        Mask |= getOverflowMask();
    return Mask;
}

unsigned long long getOverflowMask() {
    return 1ULL << (PointerBits - 1);
}
