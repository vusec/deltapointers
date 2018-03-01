#ifndef ADDRESS_SPACE_H
#define ADDRESS_SPACE_H

#include <llvm/Support/CommandLine.h>
#include <llvm/IR/Module.h> // because <llvm/IR/Type.h> fails on LLVM 3.8.0

extern llvm::cl::opt<unsigned> AddressSpaceBits;
extern llvm::cl::opt<unsigned> PointerBits;  /* FIXME: better to get this from datalayout */
extern llvm::cl::opt<bool> OverflowBit;

unsigned long long getAddressSpaceMask(bool MayPreserveOverflowBit=false);
unsigned long long getOverflowMask();

inline bool isPtrIntTy(llvm::Type *Ty) {
    return Ty->isIntegerTy(PointerBits);
}

inline llvm::IntegerType *getPtrIntTy(llvm::LLVMContext &C) {
    return llvm::Type::getIntNTy(C, PointerBits);
}

#define TAG_SHIFT       (AddressSpaceBits)
#define TAG_BITS        (PointerBits - AddressSpaceBits)
#define TAG_MASK_LOW    ((1ULL << TAG_BITS) - 1)
#define TAG_MASK_HIGH   (TAG_MASK_LOW << TAG_SHIFT)

#define BOUND_SHIFT     (TAG_SHIFT)
#define BOUND_BITS      (OverflowBit ? (TAG_BITS - 1) : TAG_BITS)
#define BOUND_MASK_LOW  ((1ULL << BOUND_BITS) - 1)
#define BOUND_MASK_HIGH (BOUND_MASK_LOW << BOUND_SHIFT)

#define ALLOWED_OOB_BYTES 0

#endif /* !ADDRESS_SPACE_H */
