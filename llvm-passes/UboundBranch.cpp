#define DEBUG_TYPE "ubound-branch"

#include "utils/Common.h"
#include "utils/CustomFunctionPass.h"
#include "AddressSpace.h"
#include "utils/Allocation.h"
#include "TagGlobalsConst.h"
#include "SafeAllocs.h"
#include "SafeAllocsOld.h"
#include "ReinterpretedPointers.h"
#include "SizeofTypes.h"
#include "LibPtrRet.h"

using namespace llvm;

struct UboundBranch : public CustomFunctionPass {
    static char ID;
    UboundBranch() : CustomFunctionPass(ID) {}

    void getAnalysisUsage(AnalysisUsage &AU) const override;

private:
    const DataLayout *DL;
    SafeAllocsBase *SafeAlloc;
    DenseMap<Function*, BasicBlock*> ErrorBlocks;
    Function *IsOOBFunc;
    Function *TrapFunc;
    Function *StrBufSizeFunc;
    Function *NewStrtokFunc;

    bool runOnFunction(Function &F) override;
    bool initializeModule(Module &M) override;

    bool instrumentGlobals(Module &M);
    bool instrumentAllocation(AllocationSite &AS);
    bool instrumentDeref(Instruction *I);
    bool instrumentMemIntrinsic(Instruction *I);
    void insertCheck(Value *Ptr, Value *DerefSize, Instruction *InsertBefore);
    BasicBlock *getOrCreateErrorBlock(Function *F);
    bool propagatePtrMetadata(Instruction *I);
    bool instrumentPtrArith(GetElementPtrInst *GEP);
    Constant *getNullPtr(PointerType *Ty);
};

char UboundBranch::ID = 0;
static RegisterPass<UboundBranch> X("ubound-branch",
        "Insert bound checks with ubound pointer in high pointer bits");

static cl::opt<bool> OptGlobal("ubound-branch-global",
        cl::desc("Tag globals"),
        cl::init(true));

static cl::opt<bool> OptHeap("ubound-branch-heap",
        cl::desc("Tag heap allocations"),
        cl::init(true));

static cl::opt<bool> OptStack("ubound-branch-stack",
        cl::desc("Tag stack allocations"),
        cl::init(true));

static cl::opt<bool> OptReplaceNull("ubound-branch-nullptr",
        cl::desc("Instrument the NULL pointer with upper bound pointer 0x1"),
        cl::init(true));

static cl::opt<bool> OptMemIntrinsics("ubound-branch-mem-intrinsics",
        cl::desc("Enable checks on memory intrinsics (e.g., memcpy)"),
        cl::init(true));

STATISTIC(NStack,         "Number of tagged stack variables");
STATISTIC(NHeap,          "Number of tagged heap allocations");
STATISTIC(NGlobal,        "Number of tagged globals");
STATISTIC(NChecks,        "Number of bound checks at loads/stores");
STATISTIC(NLibCall,       "Number of libcalls instrumented: total");
STATISTIC(NIgnore,        "Number of libcalls instrumented: Ignore");
STATISTIC(NCopyFromArg,   "Number of libcalls instrumented: CopyFromArg");
STATISTIC(NPtrDiff,       "Number of libcalls instrumented: PtrDiff");
STATISTIC(NRetSizeStatic, "Number of libcalls instrumented: RetSizeStatic");
STATISTIC(NStrlen,        "Number of libcalls instrumented: Strlen");
STATISTIC(NStrtok,        "Number of libcalls instrumented: Strtok");
STATISTIC(NGep,           "Number of pointer arithmetic instructions instrumented");
STATISTIC(NNullPtr,       "Number of NULL pointer operands replaced");
STATISTIC(NMemIntrinsic,  "Number of memory intrinsics instrumented");

void UboundBranch::getAnalysisUsage(AnalysisUsage &AU) const {
    AU.setPreservesCFG();
    AU.addPreserved<SafeAllocs>();
    AU.addPreserved<SafeAllocsOld>();
    AU.addPreserved<ReinterpretedPointers>();
    AU.addPreserved<SizeofTypes>();
    AU.addUsedIfAvailable<SafeAllocs>();
    AU.addUsedIfAvailable<SafeAllocsOld>();
}

bool UboundBranch::initializeModule(Module &M) {
    DL = &M.getDataLayout();

    if (!(SafeAlloc = getAnalysisIfAvailable<SafeAllocs>()))
        SafeAlloc = getAnalysisIfAvailable<SafeAllocsOld>();

    ErrorBlocks.clear();
    TrapFunc = Intrinsic::getDeclaration(&M, Intrinsic::trap);
    IsOOBFunc = getNoInstrumentFunction(M, "is_oob");
    StrBufSizeFunc = getNoInstrumentFunction(M, "strsize_nullsafe");
    NewStrtokFunc = getNoInstrumentFunction(M, "strtok_ubound");

    return instrumentGlobals(M);
}

bool UboundBranch::runOnFunction(Function &F) {
    bool Changed = false;
    SmallVector<GetElementPtrInst*, 8> Geps;
    SmallVector<Instruction*, 8> Derefs, MemIntrinsics;

    for (Instruction &I : instructions(F)) {
        AllocationSite AS;

        if (isAllocation(&I, AS)) {
            Changed |= instrumentAllocation(AS);
        }
        else if (isa<LoadInst>(I) || isa<StoreInst>(I)) {
            Derefs.push_back(&I);
        }
        else ifcast(GetElementPtrInst, GEP, &I) {
            Geps.push_back(GEP);
        }
        else {
            Changed |= propagatePtrMetadata(&I);
        }

        if (OptMemIntrinsics) {
            ifcast(MemIntrinsic, MI, &I) {
                MemIntrinsics.push_back(MI);
            }
            else ifcast(CallInst, CI, &I) {
                Function *CF = CI->getCalledFunction();
                if (CF && CF->hasName() && CF->getName() == "memcmp")
                    MemIntrinsics.push_back(CI);
            }
        }

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

    for (Instruction *I : Derefs)
        Changed |= instrumentDeref(I);

    for (GetElementPtrInst *GEP : Geps)
        Changed |= instrumentPtrArith(GEP);

    for (Instruction *I : MemIntrinsics)
        Changed |= instrumentMemIntrinsic(I);

    return Changed;
}

bool UboundBranch::instrumentGlobals(Module &M) {
    if (!OptGlobal)
        return false;

    for (GlobalVariable &GV : M.globals()) {
        if (!canTagGlobal(GV))
            continue;

        if (SafeAlloc && !SafeAlloc->needsTag(&GV))
            continue;

        Type *Ty = GV.getType()->getPointerElementType();
        uint64_t Size = DL->getTypeStoreSize(Ty);
        Size += ALLOWED_OOB_BYTES;

        IntegerType *PtrIntTy = getPtrIntTy(GV.getContext());
        Constant *GVInt = ConstantExpr::getPtrToInt(&GV, PtrIntTy);
        Constant *SizeInt = ConstantInt::get(PtrIntTy, Size);
        Constant *EndPtr = ConstantExpr::getAdd(GVInt, SizeInt);

        tagGlobal(GV, EndPtr);
        ++NGlobal;
    }

    return NGlobal > 0;
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
    Value *Masked = B.CreateAnd(PtrInt, getAddressSpaceMask(), Prefix + "applymask");
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
bool UboundBranch::instrumentAllocation(AllocationSite &AS) {
    if (AS.isStackAllocation() && !OptStack)
        return false;

    if (AS.isHeapAllocation() && !OptHeap)
        return false;

    IRBuilder<> B(getInsertPointAfter(AS.Allocation));
    Value *Ptr = maskMallocWrapper(B, AS);

    if (SafeAlloc && !SafeAlloc->needsTag(AS.Allocation))
        return Ptr != AS.Allocation;

    std::vector<User*> Users(Ptr->user_begin(), Ptr->user_end());

    Value *Size = AS.instrumentWithByteSize(B, *DL);
    IntegerType *SizeTy = cast<IntegerType>(Size->getType());

    if (ALLOWED_OOB_BYTES)
        Size = B.CreateAdd(Size, ConstantInt::get(SizeTy, ALLOWED_OOB_BYTES));

    Value *PtrInt = B.CreatePtrToInt(Ptr, getPtrIntTy(Ptr->getContext()));
    std::string Prefix = Ptr->hasName() ? Ptr->getName().str() + "." : "";
    Value *EndPtr = B.CreateAdd(PtrInt, Size);
    Value *TagShifted = B.CreateShl(EndPtr, AddressSpaceBits, Prefix + "tag");
    Value *Tagged = B.CreateOr(PtrInt, TagShifted, Prefix + "applytag");
    Value *NewPtr = B.CreateIntToPtr(Tagged, Ptr->getType(), Prefix + "tagged");

    for (User *U : Users)
        U->replaceUsesOfWith(Ptr, NewPtr);

    if (AS.isStackAllocation()) ++NStack; else ++NHeap;
    return true;
}

bool UboundBranch::instrumentDeref(Instruction *I) {
    int PtrOperand = isa<LoadInst>(I) ? 0 : 1;
    Value *Ptr = I->getOperand(PtrOperand);

    if (SafeAlloc && !SafeAlloc->needsMask(I, Ptr))
        return false;

    Type *DerefTy = isa<LoadInst>(I) ? I->getType() :
        cast<StoreInst>(I)->getValueOperand()->getType();
    uint64_t DerefSize = DL->getTypeStoreSize(DerefTy);

    insertCheck(Ptr, ConstantInt::get(Type::getInt64Ty(I->getContext()), DerefSize), I);
    return true;
}

bool UboundBranch::instrumentMemIntrinsic(Instruction *I) {
    Value *Length;
    Use *PtrArg1Use, *PtrArg2Use = NULL;

    ifcast(MemIntrinsic, MI, I) {
        Length = MI->getLength();
        PtrArg1Use = &MI->getRawDestUse();
        ifcast(MemTransferInst, MTI, MI) {
            PtrArg2Use = &MTI->getRawSourceUse();
        }
    }
    else ifcast(CallInst, CI, I) {
        if (CI->getCalledFunction()->getName() == "memcmp") {
            Length = CI->getArgOperand(2);
            PtrArg1Use = &CI->getArgOperandUse(0);
            PtrArg2Use = &CI->getArgOperandUse(1);
        }
        else {
            LOG_LINE("Unhandled call: " << *CI);
            llvm_unreachable("unhandled call");
        }
    }
    else {
        LOG_LINE("Unhandled intrinsic inst: " << *I);
        llvm_unreachable("unhandled inst");
    }

    insertCheck(PtrArg1Use->get(), Length, I);

    if (PtrArg2Use)
        insertCheck(PtrArg2Use->get(), Length, I);

    ++NMemIntrinsic;
    return true;
}

void UboundBranch::insertCheck(Value *Ptr, Value *DerefSize, Instruction *InsertBefore) {
    IRBuilder<> B(InsertBefore);
    std::string Prefix = Ptr->hasName() ? Ptr->getName().str() + "." : "";

    BasicBlock *BB = InsertBefore->getParent();
    BasicBlock *Succ = BB->splitBasicBlock(B.GetInsertPoint(), Prefix + "fallthru");
    cast<BranchInst>(BB->getTerminator())->eraseFromParent();
    B.SetInsertPoint(BB);
    //Value *PtrInt = B.CreatePtrToInt(Ptr, getPtrIntTy(I->getContext()), Prefix + "int");
    //Value *EndPtr = B.CreateLShr(PtrInt, AddressSpaceBits, Prefix + "endptr");
    //Value *MaskedPtr = B.CreateAnd(PtrInt, getAddressSpaceMask(), Prefix + "maskedptr");
    //Value *DerefEndPtr = B.CreateAdd(MaskedPtr, DerefSize, Prefix + "derefendptr");
    //Value *NullCheck = B.CreateICmpNE(EndPtr, B.getInt64(0), Prefix + "nullcheck");
    //Value *BoundsCheck = B.CreateICmpUGT(DerefEndPtr, EndPtr, Prefix + "boundscheck");
    //Value *IsOOB = B.CreateAnd(NullCheck, BoundsCheck, Prefix + "oob");
    Value *Ptr8 = B.CreatePointerCast(Ptr, B.getInt8PtrTy(), Prefix + "voidptr");
    Value *IsOOB = B.CreateCall(IsOOBFunc, {Ptr8, DerefSize}, Prefix + "oob");
    B.CreateCondBr(IsOOB, getOrCreateErrorBlock(BB->getParent()), Succ);

    ++NChecks;
}

BasicBlock *UboundBranch::getOrCreateErrorBlock(Function *F) {
    auto it = ErrorBlocks.find(F);
    if (it != ErrorBlocks.end())
        return it->second;

    BasicBlock *BB = BasicBlock::Create(F->getContext(), "oob_error", F);
    ErrorBlocks[F] = BB;

    IRBuilder<> B(BB);
    B.CreateCall(TrapFunc);
    B.CreateUnreachable();

    return BB;
}

bool UboundBranch::propagatePtrMetadata(Instruction *I) {
    int arg;

    if (!isa<CallInst>(I) && !isa<InvokeInst>(I))
        return false;

    CallSite CS(I);
    Function *F = CS.getCalledFunction();

    if (!F || F->isIntrinsic() || !F->isDeclaration())
        return false;

    if (SafeAlloc && !SafeAlloc->needsPropagation(I))
        return false;

    enum LibPtr type = getLibPtrType(F, &arg);

    switch (type) {
        case LibPtr::Strlen:        ++NStrlen;          break;
        case LibPtr::Ignore:        ++NIgnore;          break;
        case LibPtr::RetSizeStatic: ++NRetSizeStatic;   break;
        case LibPtr::CopyFromArg:   ++NCopyFromArg;     break;
        case LibPtr::PtrDiff:       ++NPtrDiff;         break;
        case LibPtr::Strtok:        ++NStrtok;          break;
        case LibPtr::None:                              break;
    }

    if (type == LibPtr::Ignore)
        return false;

    if (type == LibPtr::Strtok) {
        CS.setCalledFunction(NewStrtokFunc);
        ++NLibCall;
        return true;
    }
    else if (type == LibPtr::None) {
        /* Sanity check that it doesn't return pointer. */
        if (F->getReturnType()->isPointerTy()) {
            LOG_LINE("Error: unhandled ext func that returns pointer: " <<
                    F->getName() << ": " << *F->getType());
            exit(1);
        }
        return false;
    }

    IRBuilder<> B(getInsertPointAfter(I));
    Value *Ptr = I;
    std::vector<User*> Users(Ptr->user_begin(), Ptr->user_end());

    Value *PtrVal = B.CreatePtrToInt(Ptr, B.getInt64Ty());
    Value *NewEndPtr;

    if (type == LibPtr::Strlen) {
        Value *StrBufSizeArgs[] = { Ptr };
        Value *StrSize = B.CreateCall(StrBufSizeFunc, StrBufSizeArgs);
        if (ALLOWED_OOB_BYTES) {
            IntegerType *Ty = cast<IntegerType>(StrSize->getType());
            StrSize = B.CreateAdd(StrSize, ConstantInt::get(Ty, ALLOWED_OOB_BYTES));
        }
        NewEndPtr = B.CreateShl(B.CreateAdd(PtrVal, StrSize), AddressSpaceBits);
    }
    else if (type == LibPtr::RetSizeStatic) {
        Type *RetTy = F->getReturnType()->getPointerElementType();
        uint64_t Sz = DL->getTypeStoreSize(RetTy);
        NewEndPtr = B.CreateShl(B.CreateAdd(PtrVal, B.getInt64(Sz)), AddressSpaceBits);
    }
    else if (type == LibPtr::CopyFromArg || type == LibPtr::PtrDiff) {
        IntegerType *PtrIntTy = getPtrIntTy(I->getContext());
        Value *OrigPtrVal = B.CreatePtrToInt(CS.getArgOperand(arg), PtrIntTy);
        NewEndPtr = B.CreateAnd(OrigPtrVal, BOUND_MASK_HIGH);
    }

    Value *NewPtr = B.CreateIntToPtr(B.CreateOr(PtrVal, NewEndPtr), Ptr->getType());
    for (User *U : Users)
        U->replaceUsesOfWith(Ptr, NewPtr);

    ++NLibCall;
    return true;
}

bool UboundBranch::instrumentPtrArith(GetElementPtrInst *Ptr) {
    if (SafeAlloc && !SafeAlloc->hasTag(Ptr))
        return false;

    std::vector<User*> Users(Ptr->user_begin(), Ptr->user_end());

    std::string Prefix = Ptr->hasName() ? Ptr->getName().str() + "." : "";
    Type *PtrIntTy = getPtrIntTy(Ptr->getContext());
    IRBuilder<> B(getInsertPointAfter(Ptr));
    Value *BaseInt = B.CreatePtrToInt(Ptr->getPointerOperand(), PtrIntTy, Prefix + "baseint");
    Value *BaseTag = B.CreateAnd(BaseInt, BOUND_MASK_HIGH, Prefix + "basetag");
    Value *PtrInt = B.CreatePtrToInt(Ptr, PtrIntTy, Prefix + "int");
    Value *Truncated = B.CreateAnd(PtrInt, getAddressSpaceMask(), Prefix + "truncated");
    Value *Retagged = B.CreateOr(Truncated, BaseTag, Prefix + "retagged");
    Value *NewPtr = B.CreateIntToPtr(Retagged, Ptr->getType(), Prefix + "newptr");

    for (User *U : Users)
        U->replaceUsesOfWith(Ptr, NewPtr);

    ++NGep;
    return true;
}

/*
 * Replace NULL pointer with 0x0000000100000000 so that the end pointer can
 * never be mapped, but a zero-check on the metadata will produce a nonzero
 * upper bound.
 */
Constant *UboundBranch::getNullPtr(PointerType *Ty) {
    IntegerType *IntTy = IntegerType::get(Ty->getContext(), PointerBits);
    ConstantInt *IntVal = ConstantInt::get(IntTy, 1ULL << AddressSpaceBits);
    return ConstantExpr::getIntToPtr(IntVal, Ty);
}
