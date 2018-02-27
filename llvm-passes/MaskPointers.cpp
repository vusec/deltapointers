#include <llvm/ADT/TinyPtrVector.h>

#define DEBUG_TYPE "mask-pointers"

#include "utils/Common.h"
#include "utils/CustomFunctionPass.h"
#include "AddressSpace.h"
#include "GlobalOpt.h"
#include "SafeAllocs.h"
#include "SafeAllocsOld.h"
#include "ReinterpretedPointers.h"

//#define USE_MASK_HELPER

using namespace llvm;

static cl::list<std::string> FunctionIgnoreList("mask-pointers-ignore-list",
        cl::desc("List of function names to not mask pointers in"),
        cl::ZeroOrMore);

static cl::opt<std::string> UseMaskHelper("mask-pointers-helper",
        cl::desc("Name of helper function for masking"),
        cl::value_desc("function_name"));

struct MaskPointers : public CustomFunctionPass {
    static char ID;
    MaskPointers() : CustomFunctionPass(ID) {}

    virtual void getAnalysisUsage(AnalysisUsage &AU) const;

private:
    struct MaskEntry : public std::pair<Instruction*, int> {
        MaskEntry(Instruction *User, unsigned Idx, bool ForceMask) {
            first = User;
            int i = static_cast<int>(Idx);
            second = ForceMask ? -i - 1 : i;
        }

        Instruction *User() { return first; }
        unsigned OperandIndex() {
            return static_cast<unsigned>(second < 0 ? -second - 1 : second);
        }
        bool ForceMaskOverflowBit() { return second < 0; }

        Instruction *User() const { return first; }
        unsigned OperandIndex() const {
            return static_cast<unsigned>(second < 0 ? -second - 1 : second);
        }
        bool ForceMaskOverflowBit() const { return second < 0; }
    };

    Function *CheckFunc;
    Function *MaskPtrFunc;
    unsigned long long NChecks;
    MapVector<Value*, SmallSetVector<MaskEntry, 1>> Masks;  // ptrint -> [ins]
    SafeAllocsBase *SafeAlloc;
    ReinterpretedPointers *ReintPtrs;

    bool initializeModule(Module &M) override;
    bool runOnFunction(Function &F) override;
    bool finalizeModule(Module &M) override;

    bool instrumentGlobals(Module &M);
    void instrumentArgs(Function *F);
    void instrumentCallExt(CallSite *CS);
    void instrumentCallExtWrap(CallSite *CS);
    void instrumentCallByval(CallSite *CS);
    void instrumentCallExtNestedPtrs(CallSite *CS);
    void instrumentCallSafeArgs(CallSite *CS);
    void instrumentCmpPtr(CmpInst *I);
    void instrumentMemAccess(Instruction *I);
    void instrumentNullTagUsers(Instruction *PtrInt);

    void setMasks(Instruction *I, Value *Ptr, unsigned Idx, bool ForceMaskOverflowBit);
    Value *maskPointer(Value *Ptr, IRBuilder<> &B, bool ForceMaskOverflowBit=false);
    void maskPointerArgs(CallSite *CS);
    void maskNestedPointers(Value *V, CompositeType *EltTy,
            SmallVector<Value*, 4> &indices, IRBuilder<> &B);
};

char MaskPointers::ID = 0;
static RegisterPass<MaskPointers> X("mask-pointers",
        "Mask high bits of pointers at loads and stores (SFI)");

STATISTIC(NMasks,       "Number of pointers masked");
STATISTIC(NSkippedSafe, "Number of masks prevented by static analysis");
STATISTIC(NSkippedTags, "Number of masks prevented by directly using the allocation without tag");

void MaskPointers::getAnalysisUsage(AnalysisUsage &AU) const {
    AU.addPreserved<SafeAllocs>();
    AU.addPreserved<SafeAllocsOld>();
    AU.addPreserved<ReinterpretedPointers>();
    AU.addUsedIfAvailable<SafeAllocs>();
    AU.addUsedIfAvailable<SafeAllocsOld>();
    AU.addUsedIfAvailable<ReinterpretedPointers>();
}

bool MaskPointers::initializeModule(Module &M) {
    CheckFunc = getNoInstrumentFunction(M, "checkmagic", true);

    if (UseMaskHelper.getNumOccurrences()) {
        MaskPtrFunc = getNoInstrumentFunction(M, UseMaskHelper);
        MaskPtrFunc->addFnAttr(Attribute::AlwaysInline);
    } else {
        MaskPtrFunc = nullptr;
    }

    NChecks = 0;
    Masks.clear();
    if (!(SafeAlloc = getAnalysisIfAvailable<SafeAllocs>()))
        SafeAlloc = getAnalysisIfAvailable<SafeAllocsOld>();
    ReintPtrs = getAnalysisIfAvailable<ReinterpretedPointers>();
    return instrumentGlobals(M);
}

bool MaskPointers::finalizeModule(Module &M) {
    // TODO: move loop-invariant masks out of loops

    // Apply all masks while applying as few masks as possible
    IRBuilder<> B(M.getContext());

    for (auto &MI : Masks) {
        Value * const Ptr = MI.first;

        // TODO: only mask once for each pointer
        for (const MaskEntry &ME : MI.second) {
            assert(ME.User()->getOperand(ME.OperandIndex()) == Ptr);
            B.SetInsertPoint(ME.User());
            Value *Masked = maskPointer(Ptr, B, ME.ForceMaskOverflowBit());
            ME.User()->setOperand(ME.OperandIndex(), Masked);
        }
    }

    return NMasks > 0;
}

void MaskPointers::setMasks(Instruction *I, Value *Ptr, unsigned Idx, bool ForceMaskOverflowBit) {
    // Don't mask safe pointers
    if (SafeAlloc && !SafeAlloc->needsMask(I, Ptr)) {
        ++NSkippedSafe;
        return;
    }

    // TODO: optimization: don't mask in comparison with NULL (since null
    // pointers don't have metadata)

    MaskEntry Entry(I, Idx, ForceMaskOverflowBit);
    auto MI = Masks.find(Ptr);
    if (MI == Masks.end()) {
        SmallSetVector<MaskEntry, 1> Vec;
        Vec.insert(Entry);
        Masks[Ptr] = Vec;
    } else {
        // Check for duplicates
        // XXX: this is possibly inefficient
        for (const MaskEntry &ME : MI->second) {
            if (ME.User() == I && ME.OperandIndex() == Idx) {
                // Choose ForceMask=true over false, assuming that calls to
                // setmasks with ForceMask=true are certain that it is safe not
                // to preserve the overflow bit
                if (!ME.ForceMaskOverflowBit() && ForceMaskOverflowBit) {
                    MI->second.remove(ME);
                    break;
                } else {
                    return;
                }
            }
        }

        MI->second.insert(Entry);
    }
}

static Value *getAllocationFromTag(Value *Ptr) {
    Ptr = Ptr->stripPointerCasts();

    ifcast(IntToPtrInst, Cast, Ptr) {
        ifcast(BinaryOperator, Tag, Cast->getOperand(0)) {
            if (Tag->getOpcode() == Instruction::Or) {
                ifcast(ConstantInt, Mask, Tag->getOperand(1)) {
                    if (Mask->getZExtValue() > getAddressSpaceMask()) {
                        ifcast(PtrToIntInst, PtrInt, Tag->getOperand(0))
                            return PtrInt->getOperand(0);
                    }
                }
            }
        }
    }
    else ifcast(ConstantExpr, Cast, Ptr) {
        if (Cast->getOpcode() == Instruction::IntToPtr) {
            ifcast(ConstantExpr, Tag, Cast->getOperand(0)) {
                if (Tag->getOpcode() == Instruction::Or) {
                    ifcast(ConstantExpr, Allocation, Tag->getOperand(0)) {
                        if (Allocation->getOpcode() == Instruction::PtrToInt) {
                            ifcast(GlobalVariable, GV, Allocation->getOperand(0))
                                return GV;
                        }
                    }
                }
            }
        }
    }

    return nullptr;
}

Value *MaskPointers::maskPointer(Value *Ptr, IRBuilder<> &B, bool ForceMaskOverflowBit) {
    // Don't mask safe pointers
    if (SafeAlloc && !SafeAlloc->hasTag(Ptr)) {
        ++NSkippedSafe;
        return Ptr;
    }

    // Instead of doing alloc -> tag -> mask, use the alloc directly
    if (Value *Allocation = getAllocationFromTag(Ptr)) {
        ++NSkippedTags;
        return B.CreateBitCast(Allocation, Ptr->getType(), Ptr->getName());
    }

    ++NMasks;

    bool IsInt = isPtrIntTy(Ptr->getType());
    std::string Prefix = Ptr->hasName() ? Ptr->getName().str() + "." : "";
    bool Preserve = OverflowBit && !ForceMaskOverflowBit;

    if (MaskPtrFunc) {
        // Inlined helper
        if (IsInt) {
            if (CheckFunc)
                B.CreateCall(CheckFunc, {Ptr, B.getInt64(++NChecks)});
            return B.CreateCall(MaskPtrFunc, {Ptr, B.getInt1(Preserve)}, "masked");
        }
        Value *AsInt = B.CreatePtrToInt(Ptr, B.getIntNTy(PointerBits), Prefix + "int");
        if (CheckFunc)
            B.CreateCall(CheckFunc, {AsInt, B.getInt64(++NChecks)});
        Value *MaskedInt = B.CreateCall(MaskPtrFunc, {AsInt, B.getInt1(Preserve)}, "mask");
        return B.CreateIntToPtr(MaskedInt, Ptr->getType(), Prefix + "masked");
    } else {
        // TODO: dont do ptrtoint if the source is an inttoptr cast

        // AND with constant mask and leave opts up to the compiler backend
        unsigned long long Mask = getAddressSpaceMask(Preserve);
        if (IsInt) {
            if (CheckFunc)
                B.CreateCall(CheckFunc, {Ptr, B.getInt64(++NChecks)});
            return B.CreateAnd(Ptr, Mask, Prefix + "masked");
        }
        Value *AsInt = B.CreatePtrToInt(Ptr, B.getIntNTy(PointerBits), Prefix + "int");
        if (CheckFunc)
            B.CreateCall(CheckFunc, {AsInt, B.getInt64(++NChecks)});
        Value *MaskedInt = B.CreateAnd(AsInt, Mask, Prefix + "mask");
        return B.CreateIntToPtr(MaskedInt, Ptr->getType(), Prefix + "masked");
    }

#if 0
    // cmov
    Constant *Zero = B.getInt64(0);
    Value *AsInt = B.CreatePtrToInt(Ptr, B.getIntNTy(PointerBits), Prefix + "int");
    if (CheckFunc)
        B.CreateCall(CheckFunc, {AsInt, B.getInt64(++NChecks)});
    Value *Cond = B.CreateICmpSLT(AsInt, Zero, Prefix + "cmp");
    Value *DerefPtr = B.CreateSelect(Cond, Zero, AsInt, Prefix + "derefptr");
    Value *MaskedInt = B.CreateAnd(DerefPtr, getAddressSpaceMask(), Prefix + "mask");
    return B.CreateIntToPtr(MaskedInt, Ptr->getType(), Prefix + "masked");

    // other cmov
    Constant *Zero = B.getInt64(0);
    Value *AsInt = B.CreatePtrToInt(Ptr, B.getIntNTy(PointerBits), Prefix + "int");
    if (CheckFunc)
        B.CreateCall(CheckFunc, {AsInt, B.getInt64(++NChecks)});
    Value *Cond = B.CreateICmpSLT(AsInt, Zero, Prefix + "cmp");
    Value *MaskedInt = B.CreateAnd(AsInt, getAddressSpaceMask(), Prefix + "mask");
    Value *AsPtr = B.CreateIntToPtr(MaskedInt, Ptr->getType(), Prefix + "masked");
    Value *Null = B.CreateLoad(ConstantPointerNull::get(cast<PointerType>(Ptr->getType())->getPointerTo()));
    return B.CreateSelect(Cond, Null, AsPtr, Prefix + "derefptr");
#endif
}

void MaskPointers::maskPointerArgs(CallSite *CS) {
    Instruction *I = CS->getInstruction();

    for (unsigned i = 0, n = CS->getNumArgOperands(); i < n; i++) {
        Value *Arg = CS->getArgOperand(i);
        if (Arg->getType()->isPointerTy()) {
            // Preserve overflow bit so that libcalls cannot be used to
            // dereference an OOB pointer
            setMasks(I, Arg, i, false);
        }
    }
}

static bool hasPointerArg(Function *F) {
    FunctionType *FT = F->getFunctionType();
    for (unsigned i = 0, n = FT->getNumParams(); i < n; i++) {
        Type *type = FT->getParamType(i);
        if (type->isPointerTy())
            return true;
    }
    return false;
}

bool isIgnoredFunctionCall(Function *F) {
    std::string FuncName = F->getName().str();
    for (auto IgnoredFunction : FunctionIgnoreList)
        if (IgnoredFunction == FuncName)
            return true;
    return false;
}

/*
 * Mask pointers to external functions.
 * TODO: don't do this if we can determine it's not eg heap based.
 */
void MaskPointers::instrumentCallExt(CallSite *CS) {
    // Don't use getCalledFunction() directly because implicit declarations of
    // functions will result in inline bitcasts of function.
    Value *V = CS->getCalledValue()->stripPointerCasts();
    Function *F = dyn_cast<Function>(V);

    // We currently rely on non-masked asm arguments for our tests, but for
    // instance nginx needs pointers to inline asm masked.
    if (CS->isInlineAsm()) {
        maskPointerArgs(CS);
        return;
    }

    if (!F)                  /* XXX indirect calls? */
        return;
    if (!F->isDeclaration() && !F->isDeclarationForLinker()) /* not external */
        return;
    if (isIgnoredFunctionCall(F))
        return;

    if (F->isIntrinsic() && hasPointerArg(F)) {
        switch (F->getIntrinsicID()) {
            case Intrinsic::dbg_declare:
            case Intrinsic::dbg_value:
            case Intrinsic::lifetime_start:
            case Intrinsic::lifetime_end:
            case Intrinsic::invariant_start:
            case Intrinsic::invariant_end:
            case Intrinsic::eh_typeid_for:
            case Intrinsic::eh_return_i32:
            case Intrinsic::eh_return_i64:
            case Intrinsic::eh_sjlj_functioncontext:
            case Intrinsic::eh_sjlj_setjmp:
            case Intrinsic::eh_sjlj_longjmp:
                return; /* No masking */
            case Intrinsic::memcpy:
            case Intrinsic::memmove:
            case Intrinsic::memset:
            case Intrinsic::vastart:
            case Intrinsic::vacopy:
            case Intrinsic::vaend:
                break; /* Continue with masking */
            default:
                errs() << "Unhandled intrinsic that takes pointer: " << *F << "\n";
                break; /* Do mask to be sure. */
        }
    }

    // Some functions need dynamic logic to mask nested pointers in args, e.g. execve
    if (Function *WrapFunc = getNoInstrumentFunction(*F->getParent(), F->getName().str() + "_mask", true)) {
        cast<CallInst>(CS->getInstruction())->setCalledFunction(WrapFunc);
        return;
    }

    maskPointerArgs(CS);
}

/*
 * Mask pointers passed as arguments to wrapper functions for external
 * functions, that we cannot detect in the wrapper itself. This is mostly the
 * cast for wrappers of varargs functions where the wrapper just passes a
 * va_list.
 */
void MaskPointers::instrumentCallExtWrap(CallSite *CS) {
    Function *F = CS->getCalledFunction();
    if (CS->isInlineAsm() || !F)
        return;

    if (F->getName() != "_E__pr_info" && /* sphinx3 vfprintf wrapper */
        F->getName() != "_ZN12pov_frontend13MessageOutput6PrintfEiPKcz" && /* povray vsnprintf wrapper */
        F->getName() != "_ZN8pov_base16TextStreamBuffer6printfEPKcz" && /* povray vsnprintf wrapper */
        F->getName() != "_ZN3pov10Debug_InfoEPKcz" && /* povray vsnprintf wrapper */
        F->getName() != "_ZN3pov25POVMSUtil_SetFormatStringEP9POVMSDatajPKcz" && /* povray vsprintf wrapper */
        F->getName() != "_ZN6cEnvir9printfmsgEPKcz" && /* omnetpp vsprintf wrapper */
        F->getName() != "PerlIO_printf" && /* perl vprintf wrapper */
        F->getName() != "PerlIO_stdoutf")  /* perl vprintf wrapper */
        return;

    maskPointerArgs(CS);
}

void MaskPointers::instrumentCallByval(CallSite *CS) {
    Function *F = CS->getCalledFunction();
    if (CS->isInlineAsm()) /* XXX inline asm should actually be masked? */
        return;
    if (F && F->isDeclaration()) /* external functions are handled above */
        return;

    Instruction *I = CS->getInstruction();

    for (unsigned i = 0, n = CS->getNumArgOperands(); i < n; i++) {
        Value *Arg = CS->getArgOperand(i);
        if (Arg->getType()->isPointerTy() && CS->paramHasAttr(i + 1, Attribute::ByVal))
            setMasks(I, Arg, i, true);
    }
}

void MaskPointers::maskNestedPointers(Value *V, CompositeType *EltTy,
        SmallVector<Value *, 4> &indices, IRBuilder<> &B) {
    unsigned n = EltTy->isStructTy() ?
        cast<StructType>(EltTy)->getNumElements() :
        cast<ArrayType>(EltTy)->getNumElements();

    for (unsigned i = 0; i < n; i++) {
        Type *Ty = EltTy->getTypeAtIndex(i);

        if (Ty->isPointerTy()) {
            DEBUG_LINE("masking nested pointer of type " << *Ty << " in value: " << *V);
            indices.push_back(B.getInt32(i));
            Value *Ptr = B.CreateInBoundsGEP(V, indices, "nestedgep");
            indices.pop_back();
            Value *MaskedPtr = maskPointer(Ptr, B);
            Value *Load = B.CreateLoad(MaskedPtr, "nestedval");
            Value *Masked = maskPointer(Load, B);
            B.CreateStore(Masked, MaskedPtr);
        }
        else if (Ty->isAggregateType()) {
            indices.push_back(B.getInt32(i));
            maskNestedPointers(V, cast<CompositeType>(Ty), indices, B);
            indices.pop_back();
        }
    }
}

void MaskPointers::instrumentCallExtNestedPtrs(CallSite *CS) {
    static std::map<StringRef, std::vector<unsigned>> whitelist = {
        /* inlined std::list::push_back */
        {"_ZNSt8__detail15_List_node_base7_M_hookEPS0_", {1}},
        /* inlined std::string += std::string */
        {"_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_appendEPKcm", {0}}
    };
    // TODO: more generic: look for mangled std::list and push_back in fn name

    Function *F = CS->getCalledFunction();
    if (!F)
        return;

    auto it = whitelist.find(F->getName());
    if (it == whitelist.end())
        return;

    assert(F->isDeclaration());
    IRBuilder<> B(CS->getInstruction());
    SmallVector<Value *, 4> indices = {B.getInt64(0)};

    for (unsigned i : it->second) {
        Value *arg = CS->getArgOperand(i);
        Type *EltTy = cast<PointerType>(arg->getType())->getElementType();
        assert(EltTy->isAggregateType());
        DEBUG_LINE("mask nested pointers in arg " << i << " of:" << *CS->getInstruction());
        maskNestedPointers(arg, cast<CompositeType>(EltTy), indices, B);
    }
}

void MaskPointers::instrumentCallSafeArgs(CallSite *CS) {
    if (!SafeAlloc)
        return;

    Function *F = CS->getCalledFunction();
    if (!F || F->isDeclaration())
        return;

    Instruction *Call = CS->getInstruction();
    unsigned Idx = 0;

    for (Argument &Arg : F->args()) {
        Value *Param = CS->getArgument(Idx);
        if (!SafeAlloc->hasTag(&Arg) && SafeAlloc->hasTag(Param)) {
            // No need to preserve overflow bit, since all uses are safe
            setMasks(Call, Param, Idx, true);
        }
        Idx++;
    }
}

void MaskPointers::instrumentCmpPtr(CmpInst *I) {
    Value *Arg1 = I->getOperand(0);
    if (!Arg1->getType()->isPointerTy())
        return;

    Value *Arg2 = I->getOperand(1);
    assert(Arg2->getType()->isPointerTy());

    setMasks(I, Arg1, 0, true);
    setMasks(I, Arg2, 1, true);
}

/*
 * Mask out metadata bits in pointers when a pointer is accessed. It does not
 * mask out the overflow bit, so out-of-bound accesses will cause a fault.
 */
void MaskPointers::instrumentMemAccess(Instruction *I) {
    int PtrOperand = isa<StoreInst>(I) ? 1 : 0;
    Value *Ptr = I->getOperand(PtrOperand);
    setMasks(I, Ptr, PtrOperand, false);

    /* Also mask writes of pointers to externs (e.g., environ). */
    /* TODO: we don't have to mask the ptr above if global value */
    ifcast(StoreInst, SI, I) {
        ifcast(GlobalVariable, GV, Ptr->stripPointerCasts()) {
            if (!GV->hasInitializer() && GV->getType()->isPointerTy())
                setMasks(I, SI->getValueOperand(), 0, true);
        }
    }
}

/*
 * Create masks for ptrints and replace uses in users that need masking with
 * the masked value.
 */
void MaskPointers::instrumentNullTagUsers(Instruction *PtrInt) {
    assert(ReintPtrs);

    for (Instruction *User : ReintPtrs->getNullTagUsers(PtrInt)) {
        unsigned Idx = static_cast<unsigned>(getOperandNo(User, PtrInt));
        setMasks(User, PtrInt, Idx, true);
    }
}

/*
 * Mask safe uses of unsafe function arguments.
 */
void MaskPointers::instrumentArgs(Function *F) {
    if (!SafeAlloc)
        return;

    DenseMap<Argument*, SmallVector<User*, 4>> ArgMasks;

    for (Argument &Arg : F->args()) {
        if (!Arg.getType()->isPointerTy())
            continue;

        if (!SafeAlloc->hasTag(&Arg))
            continue;

        for (User *U : Arg.users()) {
            if (!SafeAlloc->hasTag(U))
                ArgMasks.FindAndConstruct(&Arg).second.push_back(U);
        }
    }

    if (ArgMasks.empty())
        return;

    IRBuilder<> B(&*F->getEntryBlock().getFirstInsertionPt());

    for (auto P : ArgMasks) {
        Argument *Arg = P.first;
        // Force overflow bit masking here, reasoning similar to that of safe
        // parameters at callsites (see finalizeModule)
        Value *Masked = maskPointer(Arg, B, true);

        for (User *U : P.second)
            U->replaceUsesOfWith(Arg, Masked);
    }
}

bool MaskPointers::runOnFunction(Function &F) {
    SmallVector<Instruction*, 10> MemoryAccesses, PtrInts;

    instrumentArgs(&F);

    for (inst_iterator II = inst_begin(&F), E = inst_end(&F); II != E; ++II) {
        Instruction *I = &*II;

        if (isa<StoreInst>(I) || isa<LoadInst>(I))
            MemoryAccesses.push_back(I);
            // TODO: fence, cmpxchg, atomicrmw

        if (ReintPtrs && ReintPtrs->hasNullTagUsers(I))
            PtrInts.push_back(I);
    }

    for (inst_iterator II = inst_begin(&F), E = inst_end(&F); II != E; ++II) {
        Instruction *I = &*II;
        if (isa<CallInst>(I) || isa<InvokeInst>(I)) {
            CallSite CS(I);
            instrumentCallExt(&CS);
            instrumentCallExtWrap(&CS);
            instrumentCallByval(&CS);
            instrumentCallExtNestedPtrs(&CS);
            instrumentCallSafeArgs(&CS);
        }
        else ifcast(CmpInst, Cmp, I) {
            instrumentCmpPtr(Cmp);
        }
        else if (SafeAlloc && !SafeAlloc->hasTag(I)) {
            ifcast(BitCastInst, BC, I) {
                if (BC->getSrcTy()->isPointerTy()) {
                    Value *Base = I->getOperand(0);
                    if (SafeAlloc->hasTag(Base))
                        setMasks(I, Base, 0, true);
                }
            }
            else if (isa<GetElementPtrInst>(I)) {
                Value *Base = I->getOperand(0);
                if (SafeAlloc->hasTag(Base))
                    setMasks(I, Base, 0, true);
            }
        }
    }

    for (Instruction *PtrInt : PtrInts)
        instrumentNullTagUsers(PtrInt);

    for (Instruction *Access : MemoryAccesses)
        instrumentMemAccess(Access);

    return true; // TODO: return false if nothing actually instruments
}

bool MaskPointers::instrumentGlobals(Module &M) {
    if (!getNoInstrumentFunction(M, "initialize_tagged_globals", true))
        return false;

    IRBuilder<> B(M.getContext());
    bool Changed = false;

    for (GlobalVariable &TaggedGV : M.globals()) {
        if (!TaggedGV.hasName() || !TaggedGV.getName().startswith("tagged."))
            continue;

        GlobalVariable *GV = M.getNamedGlobal(TaggedGV.getName().substr(7));

        /* All uses are probably constantexprs after optimizations, replace
         * them with instructions so we can replace them with loads later on */
        if (!allNonInstructionUsersCanBeMadeInstructions(GV)) {
            if (GV->hasName()) {
                DEBUG_LINE("Warning: cannot replace all references to global @"
                        << GV->getName() << ", skipping its instrumentation");
            } else {
                DEBUG_LINE("Warning: cannot replace all references to nameless "
                        << "global, skipping its instrumentation:\n" << *GV);
            }
            continue;
        }
        makeAllConstantUsesInstructions(GV);

        std::vector<User*> Users(GV->user_begin(), GV->user_end());
        for (User *U : Users) {
            Instruction *I = cast<Instruction>(U);
            Function *Parent = I->getParent()->getParent();

            if (shouldInstrument(Parent)) {
                B.SetInsertPoint(I);
                Value *TaggedPtr = B.CreateLoad(&TaggedGV, GV->getName());
                I->replaceUsesOfWith(GV, maskPointer(TaggedPtr, B));
                // TODO: one load per function
            }
        }

        Changed = true;
    }

    return Changed;
}
