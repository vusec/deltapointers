#define DEBUG_TYPE "magic-tags"

#include "builtin/Common.h"
#include "builtin/CustomFunctionPass.h"
#include "AddressSpace.h"
#include "builtin/Allocation.h"
#include "TagGlobalsConst.h"

using namespace llvm;

static cl::opt<unsigned long long> MagicValue("magic-value",
        cl::desc("Magic metadata value to put in high bits of pointers "
                 "(will be left-shifted by address-space-bits)"),
        cl::init(0xdeadbeefdeadbeefULL));

static cl::opt<bool> AllowZeroMagic("allow-zero-magic",
        cl::desc("Do not require all pointers to have the magic metadata when checking at masking"),
        cl::init(false));

struct MagicTags : public CustomFunctionPass {
    static char ID;
    MagicTags() : CustomFunctionPass(ID) {}

private:
    bool initializeModule(Module &M) override;
    bool runOnFunction(Function &F) override;

    bool instrumentGlobals(Module &M);
    void instrumentAllocation(AllocationSite &AS);
    Function *createCheckFunc(Module &M);
};

char MagicTags::ID = 0;
static RegisterPass<MagicTags> X("magic-tags",
        "Tag pointers with magic metadata (run before -mask-pointers)");

STATISTIC(NStack,  "Number of tagged stack variables");
STATISTIC(NHeap,   "Number of tagged heap allocations");
STATISTIC(NGlobal, "Number of tagged globals");

bool MagicTags::instrumentGlobals(Module &M) {
    for (GlobalVariable &GV : M.globals()) {
        if (!canTagGlobal(GV))
            continue;

        tagGlobal(GV, MagicValue);
        ++NGlobal;
    }

    return NGlobal > 0;
}

bool MagicTags::initializeModule(Module &M) {
    uint64_t Magic = (MagicValue << AddressSpaceBits) >> AddressSpaceBits;
    DEBUG_LINE("Tagging pointers with magic value 0x" << hex(Magic));

    assert(getNoInstrumentFunction(M, "checkmagic", true) == nullptr);
    createCheckFunc(M);

    instrumentGlobals(M);

    return true;
}

void MagicTags::instrumentAllocation(AllocationSite &AS) {
    Instruction *Ptr = AS.Allocation;
    IRBuilder<> B(getInsertPointAfter(Ptr));
    SmallVector<User*, 8> Users(Ptr->user_begin(), Ptr->user_end());

    Value *MagicMask = B.getIntN(PointerBits, MagicValue << AddressSpaceBits);
    Value *PtrInt = B.CreatePtrToInt(Ptr, B.getIntNTy(PointerBits), "ptrint");
    Value *Masked = B.CreateOr(PtrInt, MagicMask, "magicmask");
    std::string Name = (Ptr->hasName() ? Ptr->getName().str() : "_anon") + ".magic";
    Value *MagicPtr = B.CreateIntToPtr(Masked, Ptr->getType(), Name);

    for (User *U : Users)
        U->replaceUsesOfWith(Ptr, MagicPtr);
}

bool MagicTags::runOnFunction(Function &F) {
    unsigned long long Nold = NStack + NHeap;

    for (inst_iterator II = inst_begin(&F), E = inst_end(&F); II != E; ++II) {
        Instruction *I = &*II;
        AllocationSite AS;

        if (isAllocation(I, AS)) {
            instrumentAllocation(AS);
            if (AS.isStackAllocation())
                ++NStack;
            else
                ++NHeap;
        }
    }

    return NStack + NHeap > Nold;
}

Function *MagicTags::createCheckFunc(Module &M) {
    LLVMContext &C = M.getContext();
    Type *VoidTy = Type::getVoidTy(C);
    Type *i32Ty = Type::getInt32Ty(C);
    Type *i64Ty = Type::getInt64Ty(C);
    Type *i8PtrTy = Type::getInt8Ty(C)->getPointerTo();
    Type *PtrIntTy = getPtrIntTy(C);

    Type *PrintfArgTypes[] = {i32Ty, i8PtrTy};
    FunctionType *PrintfTy = FunctionType::get(i32Ty, PrintfArgTypes, true);
    Function *Printf = cast<Function>(M.getOrInsertFunction("dprintf", PrintfTy));

    Type *ArgTypes[] = {PtrIntTy, i64Ty};
    FunctionType *FnTy = FunctionType::get(VoidTy, ArgTypes, false);
    Function *F = createNoInstrumentFunction(M, FnTy, "checkmagic", true);
    F->addFnAttr(Attribute::AlwaysInline);

    BasicBlock *Entry = BasicBlock::Create(F->getContext(), "entry", F);
    BasicBlock *Trap = BasicBlock::Create(C, "trap", F);
    BasicBlock *Exit = BasicBlock::Create(C, "exit", F);

    auto it = F->getArgumentList().begin();
    Value *PtrInt = &*it++;
    Value *CheckID = &*it;

    IRBuilder<> B(Entry);
    Value *HighBits = B.CreateLShr(PtrInt, AddressSpaceBits, "highbits");

    if (AllowZeroMagic) {
        BasicBlock *NonZero = BasicBlock::Create(C, "nonzero", F, Trap);
        Value *Cond1 = B.CreateICmpNE(HighBits, B.getIntN(PointerBits, 0));
        B.CreateCondBr(Cond1, NonZero, Exit);
        B.SetInsertPoint(NonZero);
    }

    unsigned long long Magic = (MagicValue << AddressSpaceBits) >> AddressSpaceBits;
    Value *Cond2 = B.CreateICmpNE(HighBits, B.getIntN(PointerBits, Magic));
    B.CreateCondBr(Cond2, Trap, Exit);

    B.SetInsertPoint(Trap);
    Value *Format = B.CreateGlobalStringPtr(
            "high bits %llx in pointer %llx do not match magic value (check %llu)\n",
            NOINSTRUMENT_PREFIX "checkmagic_error");
    Value *Fd = B.getInt32(2);
    Value *PrintfArgs[] = {Fd, Format, HighBits, PtrInt, CheckID};
    B.CreateCall(Printf, PrintfArgs);
    B.CreateCall(Intrinsic::getDeclaration(&M, Intrinsic::trap));
    B.CreateUnreachable();
    //B.CreateBr(Exit);

    B.SetInsertPoint(Exit);
    B.CreateRetVoid();

    return F;
}
