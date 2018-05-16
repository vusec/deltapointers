#include "builtin/Common.h"
#include "TagGlobalsConst.h"
#include "AddressSpace.h"

using namespace llvm;

bool canTagGlobal(GlobalVariable &GV) {
    if (GV.getName().startswith("llvm."))
        return false;

    if (isNoInstrument(&GV))
        return false;

    if (GV.getNumUses() == 0)
        return false;

    // Ignore vtables because those may be dereferenced by libc
    //if (GV.getName().startswith("_ZTV"))
    //    return false;

    // Ignore typeinfo pointers
    if (GV.getName().startswith("_ZT"))
        return false;

    return true;
}

void tagGlobal(GlobalVariable &GV, uint64_t Tag) {
    tagGlobal(GV, ConstantInt::get(getPtrIntTy(GV.getContext()), Tag));
}

void tagGlobal(GlobalVariable &GV, Constant *Tag) {
    SmallVector<User*, 10> Users(GV.user_begin(), GV.user_end());

    IntegerType *PtrIntTy = getPtrIntTy(GV.getContext());
    Constant *GVInt = ConstantExpr::getPtrToInt(&GV, PtrIntTy);
    Constant *TagShifted = ConstantExpr::getShl(Tag, ConstantInt::get(PtrIntTy, AddressSpaceBits));
    Constant *TaggedGVInt = ConstantExpr::getOr(GVInt, TagShifted);
    Constant *TaggedGV = ConstantExpr::getIntToPtr(TaggedGVInt, GV.getType());

    for (User *U : Users) {
        // Ignore constantexprs, they should have been removed by
        // -expand-const-global-users
        ifncast(Instruction, UI, U)
            continue;

// XXX commented this because it screwed with global tagging in ubound-masks. It
// should be redundant anyway because of getAllocationFromTag in mask-pointers
#if 0
        // Don't add metadata to loads/stores since we'll just have to mask
        // it out again
        if (isa<LoadInst>(U))
            continue;

        ifcast(StoreInst, SI, U) {
            if (SI->getPointerOperand() == &GV)
                continue;
        }
#endif

        Function *F = UI->getParent()->getParent();

        if (!shouldInstrument(F))
            continue;

        // Skip static global constructors which would store tagged global
        // pointers in objects which are later dereferenced by free()
        if (F->hasName() && F->getName().startswith("_GLOBAL__sub_I_"))
            continue;

        U->replaceUsesOfWith(&GV, TaggedGV);
    }
}
