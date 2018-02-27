#define DEBUG_TYPE "size-tag-alloc"

#include "utils/Common.h"
#include "utils/CustomFunctionPass.h"
#include "AddressSpace.h"
#include "utils/Allocation.h"
#include "TagGlobalsConst.h"
#include "SafeAllocs.h"
#include "SafeAllocsOld.h"
#include "ReinterpretedPointers.h"
#include "SizeofTypes.h"

/*
 * TODO:
 *  - custom mem allocators
 *  - saturation arith (look into x86_64 possibilities and perf)
 *  - ARM bench: better support imm64 and saturation arith (not for gpr?)
 *  - check amount of dyn ptr arith
 *  - check amount of negative ptr arith
 *  - check alloc sizes
 *
 *  null ptr derefs
 */

using namespace llvm;

struct SizeTagAlloc : public CustomFunctionPass {
    static char ID;
    SizeTagAlloc() : CustomFunctionPass(ID) {}

    void getAnalysisUsage(AnalysisUsage &AU) const override;

private:
    const DataLayout *DL;
    SafeAllocsBase *SafeAlloc;
    SizeofTypes *SizeofAnalysis;

    bool runOnFunction(Function &F) override;
    bool initializeModule(Module &M) override;

    bool instrumentGlobals(Module &M);
    void instrumentAllocation(AllocationSite &AS);
    uint64_t derefALignmentBytes(Type *Ty);
    Type *getAllocatedElementType(AllocationSite &AS);
    Constant *getNullPtr(PointerType *Ty);
};

char SizeTagAlloc::ID = 0;
static RegisterPass<SizeTagAlloc> X("size-tag-alloc",
        "Encode object size in high bits of pointers for bounds checking");

static cl::opt<bool> OptGlobal("size-tag-global",
        cl::desc("Tag globals"),
        cl::init(true));

static cl::opt<bool> OptHeap("size-tag-heap",
        cl::desc("Tag heap allocations"),
        cl::init(true));

static cl::opt<bool> OptStack("size-tag-stack",
        cl::desc("Tag stack allocations"),
        cl::init(true));

static cl::opt<bool> OptOverinit("sizetags-overinit",
        cl::desc("Add (allocsize - 1) initial offset to size tag"),
        cl::init(false));

static cl::opt<bool> OptReplaceNull("sizetags-nullptr",
        cl::desc("Instrument the NULL pointer with a size tag that always overflows on arith"),
        cl::init(true));

STATISTIC(NStack,   "Number of tagged stack variables");
STATISTIC(NHeap,    "Number of tagged heap allocations");
STATISTIC(NGlobal,  "Number of tagged globals");
STATISTIC(NNullPtr, "Number of NULL pointer operands replaced");

void SizeTagAlloc::getAnalysisUsage(AnalysisUsage &AU) const {
    AU.setPreservesCFG();
    AU.addPreserved<SafeAllocs>();
    AU.addPreserved<SafeAllocsOld>();
    AU.addPreserved<ReinterpretedPointers>();
    AU.addPreserved<SizeofTypes>();
    AU.addUsedIfAvailable<SafeAllocs>();
    AU.addUsedIfAvailable<SafeAllocsOld>();
    AU.addUsedIfAvailable<SizeofTypes>();
}

bool SizeTagAlloc::instrumentGlobals(Module &M) {
    if (!OptGlobal)
        return false;

    for (GlobalVariable &GV : M.globals()) {
        if (!canTagGlobal(GV))
            continue;

        if (SafeAlloc && !SafeAlloc->needsTag(&GV))
            continue;

        Type *Ty = GV.getType()->getPointerElementType();
        uint64_t MaxByteOffset = DL->getTypeStoreSize(Ty);
        if (OptOverinit)
            MaxByteOffset -= derefALignmentBytes(Ty);
        MaxByteOffset += ALLOWED_OOB_BYTES;
        uint64_t Tag = -MaxByteOffset & BOUND_MASK_LOW;
        tagGlobal(GV, Tag);
        ++NGlobal;
    }

    return NGlobal > 0;
}

bool SizeTagAlloc::initializeModule(Module &M) {
    DL = &M.getDataLayout();
    if (!(SafeAlloc = getAnalysisIfAvailable<SafeAllocs>()))
        SafeAlloc = getAnalysisIfAvailable<SafeAllocsOld>();
    SizeofAnalysis = getAnalysisIfAvailable<SizeofTypes>();
    return instrumentGlobals(M);
}

/*
 * Mask out any metadata from nested allocation functions
 */
static Value *maskMallocWrapper(IRBuilder<> &B, AllocationSite &AS) {
    if (!AS.isHeapAllocation() || !AS.IsWrapped)
        return AS.Allocation;

    Value *Ptr = AS.Allocation;
    std::vector<User*> Users(Ptr->user_begin(), Ptr->user_end());

    std::string Prefix = Ptr->hasName() ? Ptr->getName().str() + "." : "";
    Value *PtrInt = B.CreatePtrToInt(Ptr, getPtrIntTy(Ptr->getContext()), Prefix + "int");
    Value *Masked = B.CreateAnd(PtrInt, getAddressSpaceMask(), Prefix + "mask");
    Value *NewPtr = B.CreateIntToPtr(Masked, Ptr->getType(), Prefix + "unwrapped");

    for (User *U : Users)
        U->replaceUsesOfWith(Ptr, NewPtr);

    return NewPtr;
}

/*
 * Put the inverse size in the upper bits of an allocated pointer, and replace
 * all occurences of this value with the instrumented pointer. IRBuilder will
 * do const prop on size, often yielding a single `or` instruction.
 */
void SizeTagAlloc::instrumentAllocation(AllocationSite &AS) {
    if (AS.isStackAllocation() && !OptStack)
        return;

    if (AS.isHeapAllocation() && !OptHeap)
        return;

    IRBuilder<> B(getInsertPointAfter(AS.Allocation));
    Value *Ptr = maskMallocWrapper(B, AS);

    if (SafeAlloc && !SafeAlloc->needsTag(AS.Allocation))
        return;

    std::vector<User*> Users(Ptr->user_begin(), Ptr->user_end());

    Value *Size = AS.instrumentWithByteSize(B, *DL);
    IntegerType *SizeTy = cast<IntegerType>(Size->getType());

    if (OptOverinit) {
        if (uint64_t AlignBytes = derefALignmentBytes(getAllocatedElementType(AS)))
            Size = B.CreateSub(Size, ConstantInt::get(SizeTy, AlignBytes));
    }

    if (ALLOWED_OOB_BYTES)
        Size = B.CreateAdd(Size, ConstantInt::get(SizeTy, ALLOWED_OOB_BYTES));

    // XXX add debug mode that inserts an assertion on the size limit?
    Value *InvSz = B.CreateAnd(B.CreateNeg(Size), BOUND_MASK_LOW);
    Value *SizeMask = B.CreateShl(InvSz, BOUND_SHIFT);

    Value *PtrInt = B.CreatePtrToInt(Ptr, B.getInt64Ty());
    Value *Tagged = B.CreateOr(PtrInt, SizeMask);
    Value *NewPtr = B.CreateIntToPtr(Tagged, Ptr->getType(), Twine(Ptr->getName()) + ".tagged");

    for (User *U : Users)
        U->replaceUsesOfWith(Ptr, NewPtr);

    if (AS.isStackAllocation()) ++NStack; else ++NHeap;
}

bool SizeTagAlloc::runOnFunction(Function &F) {
    unsigned long long Nold = NStack + NHeap;

    for (Instruction &I : instructions(F)) {
        AllocationSite AS;
        if (isAllocation(&I, AS))
            instrumentAllocation(AS);

        if (OptReplaceNull) {
            // Skip libcalls (indirect calls may be libcalls as well, ignore
            // those for now and hope they are never called with NULL args)
            if (isa<CallInst>(I) || isa<InvokeInst>(I)) {
                Function *F = CallSite(&I).getCalledFunction();
                if (F && F->isDeclaration())
                    continue;
            }

            for (Use &U : I.operands()) {
                ifcast(ConstantPointerNull, NullPtr, U.get()) {
                    U.set(getNullPtr(NullPtr->getType()));
                    NNullPtr++;
                }
            }
        }
    }

    return NStack + NHeap > Nold;
}

uint64_t SizeTagAlloc::derefALignmentBytes(Type *Ty) {
    if (isa<ArrayType>(Ty) || isa<VectorType>(Ty))
        return derefALignmentBytes(cast<SequentialType>(Ty)->getElementType());

    ifcast(StructType, StructTy, Ty)
        return derefALignmentBytes(StructTy->getElementType(StructTy->getNumElements() - 1));

    assert(Ty->isSized());
    return DL->getTypeStoreSize(Ty) - 1;
}

Type *SizeTagAlloc::getAllocatedElementType(AllocationSite &AS) {
    // Stack allocations are trivial, the alloca encodes the type
    if (AS.isStackAllocation()) {
        Type *Ty = cast<AllocaInst>(AS.Allocation)->getAllocatedType();

        // In its great wisdom, the LLVM god decides to allocate structs that
        // fit within an int type as that int and then cast it, causing our
        // offset to become 1 and thus failing struct member accesses.
        // Catch that case here by recognizing the pattern:
        // %tmpcast = bitcast cast (alloca int) to %struct.X*
        if (Ty->isIntegerTy()) {
            int IsCast = 0;

            for (User *U : AS.Allocation->users()) {
                ifncast(BitCastInst, BC, U)
                    continue;
                if (!isa<PointerType>(BC->getDestTy()))
                    continue;

                Type *DstTy = BC->getDestTy()->getPointerElementType();

                // In case of multiple casts, pick the smallest destination type
                if (DL->getTypeStoreSize(DstTy) < DL->getTypeStoreSize(Ty)) {
                    Ty = DstTy;
                    IsCast = (BC->hasName() && BC->getName().startswith("tmpcast")) ? 2 : 1;
                }
            }

            if (IsCast == 1)
                DEBUG_LINE("alloca cast: " << *AS.Allocation << " (smaller type: " << *Ty << ")");
            else if (IsCast == 2)
                DEBUG_LINE("fake alloca: " << *AS.Allocation << " (real type: " << *Ty << ")");
        }

        return Ty;
    }

    // malloc-like calls may use sizeof(elementty) at source level, use that
    // annotation here
    if (SizeofAnalysis) {
        // Note: for arrays, this returns the element type, NOT the array type
        if (Type *SizeofTy = SizeofAnalysis->getSizeofType(AS.Allocation))
            return SizeofTy;
    }

    // TODO: C++ new

    return Type::getInt8Ty(AS.Allocation->getContext());
}

Constant *SizeTagAlloc::getNullPtr(PointerType *Ty) {
    IntegerType *IntTy = IntegerType::get(Ty->getContext(), PointerBits);
    ConstantInt *IntVal = ConstantInt::get(IntTy, BOUND_MASK_HIGH);
    return ConstantExpr::getIntToPtr(IntVal, Ty);
}
