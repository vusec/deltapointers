#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/Analysis/ScalarEvolutionExpander.h>
#include <llvm/Analysis/MemoryBuiltins.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/ADT/TinyPtrVector.h>

#define DEBUG_TYPE "safe-allocs-old"

#include "builtin/Common.h"
#include "builtin/CustomFunctionPass.h"
#include "builtin/Allocation.h"
#include "AddressSpace.h"
#include "TagGlobalsConst.h"
#include "SafeAllocsOld.h"
#include "LibPtrRet.h"

using namespace llvm;

enum BasedOn { Directly, WithDiff, NotBased };

struct SafeAllocsOld::BoundT {
    int64_t Low;
    int64_t High;

    BoundT(int64_t L = -1, int64_t H = -1) : Low(L), High(H) {}

    inline bool unknown() const {
        return Low == -1 && High == -1;
    }

    inline bool unknown() {
        return Low == -1 && High == -1;
    }

    operator bool() const {
        return !unknown();
    }

    operator bool() {
        return !unknown();
    }

    const std::string str() {
        return static_cast<const BoundT*>(this)->str();
    }

    const std::string str() const {
        return std::string("{") + std::to_string(Low) + ", " + std::to_string(High) + "}";
    }
};

char SafeAllocsOld::ID = 0;
static RegisterPass<SafeAllocsOld> X("safe-allocs-old",
        "Find allocations that are only referenced inbounds",
        false, true);

STATISTIC(NArg,             "Number of safe function arguments");
STATISTIC(NStack,           "Number of safe stack allocations");
STATISTIC(NHeap,            "Number of safe heap allocations");
STATISTIC(NGlobal,          "Number of safe globals");
STATISTIC(NGep,             "Estimated number of pointer arithmetic instrumentations prevented");
STATISTIC(NDeref,           "Estimated number of load/store masks prevented");
STATISTIC(NCall,            "Estimated number of callsite parameter masks prevented");
STATISTIC(NHoistedGep,      "Number of pointer arithmetic instructions hoisted from loop bodies");
STATISTIC(NPreemptedChecks, "Number of bound checks preempted (merged with other GEP of same base pointer)");

static const unsigned MaxTraverseDepth = 1;

static void setSafeName(Value *V) {
    if (V->hasName())
        V->setName(Twine("safe.") + V->getName());
    else
        V->setName("safe.anon");
}

void SafeAllocsOld::getAnalysisUsage(AnalysisUsage &AU) const {
    AU.addRequired<TargetLibraryInfoWrapperPass>();
    AU.addRequired<LoopInfoWrapperPass>();
    AU.addRequired<ScalarEvolutionWrapperPass>();

    AU.setPreservesCFG();
    AU.addPreserved<TargetLibraryInfoWrapperPass>();
    AU.addPreserved<LoopInfoWrapperPass>();
}

bool SafeAllocsOld::isSafe(Value *Ptr) {
    return SafePointers.count(Ptr) > 0;
}

static BasedOn isRetValBasedOn(CallSite &CS, Value *Param) {
    if (Function *F = CS.getCalledFunction()) {
        int Arg;
        switch (getLibPtrType(F, &Arg)) {
            case CopyFromArg:
                if (CS.getArgOperand(Arg) == Param)
                    return Directly;
                break;
            case PtrDiff:
            case Strtok:
                if (CS.getArgOperand(Arg) == Param)
                    return WithDiff;
                break;
            default:
                break;
        }
    }
    return NotBased;
}

bool SafeAllocsOld::isSafePtr(Value *Ptr, uint64_t size) {
    // check if ptr is always inbounds with respect to its base object
    // e.g., it is a field access or an array access with constant inbounds index
    // NOTE: adapted from isSafeAccess from AddressSanitizer.cpp in LLVM
    ObjectSizeOffsetVisitor ObjSizeVis(*DL, TLI, Ptr->getContext(), true);
    SizeOffsetType objSizeOffset = ObjSizeVis.compute(Ptr);
    if (!ObjSizeVis.bothKnown(objSizeOffset)) return false;

    // TODO: SCEV based analysis

    uint64_t objSize = objSizeOffset.first.getZExtValue();
    int64_t objOffset = objSizeOffset.second.getSExtValue();

    // Three checks are required to ensure safety:
    // . objOffset >= 0  (since the offset is given from the base ptr)
    // . objSize >= objOffset  (unsigned)
    // . objSize - objOffset >= size  (unsigned)
    return objOffset >= 0 && objSize >= uint64_t(objOffset) &&
        objSize - uint64_t(objOffset) >= size / 8;
}

bool SafeAllocsOld::isUnsafeDeref(Instruction *I, BoundsT &PtrBounds, unsigned Depth) {
    if (UnsafeDerefs.count(I))
        return true;

    Value *Ptr;
    ifcast(StoreInst, SI, I)
        Ptr = SI->getPointerOperand();
    else
        Ptr = cast<LoadInst>(I)->getPointerOperand();

    // First, use our own recorded bound
    if (const BoundT Bound = PtrBounds.lookup(Ptr)) {
        if (Bound.Low <= 0 && Bound.High > 0)
            return false;

        // TODO: enable this error for non-argument allocations

        // Pointers can go out of bounds when exploring function arguments with
        // a hypothetical bound. In that case, just don't mark it as safe.
        //if (Depth == MaxTraverseDepth) {
        //    LOG_LINE("Warning: out of bounds dereference (bound: " <<
        //             Bound.str() << "):\n" << *Ptr << "\n" << *I);
        //    exit(1);
        //}

        return true;
    }

    // If no bound is recorded, fall back to basic analysis from LLVM
    unsigned size = Ptr->getType()->getPointerElementType()->getPrimitiveSizeInBits() / 8;

    if (!isSafePtr(Ptr, size)) {
        if (MaxTraverseDepth == 0)
            UnsafeDerefs.insert(I);
        return true;
    }

    return false;
}

bool SafeAllocsOld::isPtrUseSafe(Instruction *U, Value *Ptr,
        BoundsT &PtrBounds, unsigned Depth) {
    if (Visited.count(std::make_pair(U, Ptr)) > 0)
        return true;
    Visited.insert(std::make_pair(U, Ptr));

    if (isSafe(Ptr))
        return true;

    const BoundT Bound = PtrBounds.lookup(Ptr);

    if (isa<LoadInst>(U)) {
        if (!isUnsafeDeref(U, PtrBounds, Depth))
            return true;
    }
    else ifcast(StoreInst, SI, U) {
        // Pointers stored in memory are always unsafe
        if (SI->getValueOperand() == Ptr)
            return false;
        if (!isUnsafeDeref(SI, PtrBounds, Depth))
            return true;
    }
    else ifcast(MemIntrinsic, MI, U) {
        // We only support byte pointers
        ifcast(MemTransferInst, MTI, U)
            assert(MTI->getRawSource()->getType()->getPointerElementType()->isIntegerTy(8));
        assert(MI->getRawDest()->getType()->getPointerElementType()->isIntegerTy(8));

        // Check if ptr + len is inbounds
        ifcast(ConstantInt, Len, MI->getLength()) {
            if (Bound) {
                if (Len->getSExtValue() > Bound.High) {
                    return false;
                    // TODO: enable this error for non-argument allocations
                    //LOG_LINE("Error: out of bounds mem intrinsic (bound: " <<
                    //         Bound.str() << "):\n" << *Ptr << "\n" << *MI);
                    //exit(1);
                }
                return true;
            }
        }
        return false;
    }
    else ifcast(IntrinsicInst, II, U) {
        switch (II->getIntrinsicID()) {
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
                return true;
            case Intrinsic::vastart:
            case Intrinsic::vacopy:
            case Intrinsic::vaend:
                // XXX: is this correct?
                return true;
            default:
                return false;
        }
    }
    else ifcast(GetElementPtrInst, GEP, U) {
        // XXX Right now we only return true here if we can track the bounds,
        // is this too conservative?
        if (Bound) {
            APInt Offset(64, 0);
            if (GEP->accumulateConstantOffset(*DL, Offset)) {
                // TODO: enable this warning for non-argument allocations
                //if (Offset.slt(Bound.Low) || Offset.sgt(Bound.High)) {
                //    // No warning for pointers to the end of the object since
                //    // these ar common in intermediate pointers
                //    DEBUG_LINE("Warning: out of bounds GEP (bound: " <<
                //               Bound.str() << "):\n" << *GEP);
                //}
                int64_t Diff = Offset.getSExtValue();
                PtrBounds[GEP] = BoundT(Bound.Low - Diff, Bound.High - Diff);

                if (areAllPtrUsesSafe(GEP, PtrBounds, Depth))
                    return true;
            }
        }
    }
    else ifcast(BitCastInst, BC, U) {
        if (BC->getDestTy()->isPointerTy()) {
            if (Bound)
                PtrBounds[BC] = Bound;
            if (areAllPtrUsesSafe(BC, PtrBounds, Depth))
                return true;
        }
    }
    else if (isa<CallInst>(U) || isa<InvokeInst>(U)) {
        CallSite CS(U);
        Function *F = CS.getCalledFunction();
        if (isNoInstrument(F)) {
            /* XXX add more? */
            if (F->getName().startswith(std::string(NOINSTRUMENT_PREFIX) + "rts_"))
                return true;
        }
        if (F) {
            if (F->isDeclaration()) {
                // libptrret functions that copy metadata from arguments are
                // essentially GEPs
                switch (isRetValBasedOn(CS, Ptr)) {
                    case Directly:
                        if (Bound)
                            PtrBounds[U] = Bound;
                        return areAllPtrUsesSafe(U, PtrBounds, Depth);
                    case WithDiff:
                        // Cannot set bound, don't know the diff statically
                        return areAllPtrUsesSafe(U, PtrBounds, Depth);
                    case NotBased:
                        return true;
                }
            } else {
                // Inter-procedural analysis: traverse into the callee, copying
                // the pointer bound to the argument
                unsigned Idx = static_cast<unsigned>(getOperandNo(U, Ptr));
                Argument *Arg = getFunctionArgument(F, Idx);
                if (Arg) {
                    if (isSafe(Arg))
                        return true;
                    if (Depth > 0) {
                        BoundsT NestedPtrBounds;
                        if (Bound)
                            NestedPtrBounds[Arg] = Bound;
                        if (areAllPtrUsesSafe(Arg, NestedPtrBounds, Depth - 1))
                            return true;
                    }
                }
            }
        }
    }
    else if (isa<CmpInst>(U)) {
        return true;
    }
    else if (isa<PtrToIntInst>(U)) {
        return false; // XXX perlbench fix
        // Ptrint is safe if all users mask away metadata
        //if (ReintPtrs && ReintPtrs->hasNullTagUsers(U) &&
        //        ReintPtrs->getNullTagUsers(U).size() == U->getNumUses())
        //    // TODO: check if not store
        //    return true;
        //}
    }

    //DEBUG_LINE("unsafe use of:");
    //DEBUG_LINE(*Ptr);
    //DEBUG_LINE("is:");
    //DEBUG_LINE(*U);
    return false;
}

bool SafeAllocsOld::areAllPtrUsesSafe(Value *Ptr, BoundsT &PtrBounds, unsigned Depth) {
    for (auto P : usersThroughPHINodes(Ptr)) {
        // ConstantExpr uses of globals may remain in noinstrument functions
        ifcast(Instruction, UI, P.second) {
            if (!isPtrUseSafe(UI, P.first, PtrBounds, Depth)) {
                //DEBUG_LINE("unsafe use of" << *P.first << ":");
                //DEBUG(UI->dump());
                return false;
            }
        }
    }
    return true;
}

void SafeAllocsOld::setSafe(Instruction *I, Value *Ptr) {
    switch (I->getOpcode()) {
        case Instruction::Load:
        case Instruction::Store:
            ++NDeref;
            return;
        case Instruction::GetElementPtr:
            ++NGep;
        case Instruction::BitCast:
            break;
        case Instruction::Call:
        case Instruction::Invoke: {
            ++NCall;
            CallSite CS(I);
            Function *F = CS.getCalledFunction();
            if (F && !F->isDeclaration())
                return;
            if (isRetValBasedOn(CS, Ptr) == NotBased)
                return;
            break;
        }
        case Instruction::PHI:
            // TODO: tag safe if all incoming values are safe
            return;
        default:
            return;
    }

    //DEBUG_LINE("safe:" << *I);
    setSafeName(I);
    SafePointers.insert(I);
    foreach(Instruction, UI, I->users())
        setSafe(UI, I);
}

static std::string getPrefix(Instruction *I) {
    return I->hasName() ? I->getName().str() + "." : "";
}

bool SafeAllocsOld::hasHoistableIndices(GetElementPtrInst *GEP) {
    // Only handle GEPs in natural loops
    Loop *L = LI->getLoopFor(GEP->getParent());
    if (!L || !L->getLoopPreheader())
        return false;

    // Ignore safe global GEPs
    if (isSafe(GEP))
        return false;

    // The base pointer must be defined before the loop to be able to hoist its
    // offsets
    Value *Base = GEP->getPointerOperand();
    ifcast(Instruction, BaseI, Base) {
        if (L->contains(BaseI))
            return false;
    }
    assert(L->isLoopInvariant(Base));  // XXX only check this instead of contains()?

    // Find leading const offsets
    unsigned i, N = GEP->getNumOperands();
    bool NonZero = false;
    for (i = 1; i < N; i++) {
        ifncast(ConstantInt, C, GEP->getOperand(i))
            break;
        if (C->getSExtValue() != 0)
            NonZero = true;
    }

    // Don't expand if all zero
    if (!NonZero)
        return false;

    // Don't split non-constant and all-constant GEPs
    if (i == 1 || i == N)
        return false;

    return true;
}

/*
 * For unsafe(?) GEPs inside loops that start with a number of constant
 * offsets, and insert a new GEP with the constant offsets above the loop.
 */
void SafeAllocsOld::hoistConstGEPOffsetsFromLoops(Function &F, bool &Changed) {
    SmallVector<GetElementPtrInst*, 4> GEPsToReplace;

    for (inst_iterator II = inst_begin(&F), E = inst_end(&F); II != E; ++II) {
        Instruction *I = &*II;
        ifcast(GetElementPtrInst, GEP, I) {
            if (hasHoistableIndices(GEP))
                GEPsToReplace.push_back(GEP);
        }
    }

    SmallVector<Value*, 4> ConstIdx, DynIdx;

    for (GetElementPtrInst *GEP : GEPsToReplace) {
        DEBUG(errs() << "split looping GEP:\n");
        DEBUG(errs() << "  " << *GEP->getType() << "  ");
        DEBUG(GEP->dump());

        Loop *L = LI->getLoopFor(GEP->getParent());
        IRBuilder<> B(L->getLoopPreheader()->getTerminator());

        // Collect leading constant indices
        unsigned i, N = GEP->getNumOperands();
        ConstIdx.clear();
        ConstIdx.reserve(N - 1);
        for (i = 1; i < N; i++) {
            ifcast(ConstantInt, C, GEP->getOperand(i))
                ConstIdx.push_back(C);
            else
                break;
        }

        // Collect remaining dynamic indices
        DynIdx.clear();
        DynIdx.reserve(N - ConstIdx.size());
        DynIdx.push_back(B.getInt32(0));
        while (i < N)
            DynIdx.push_back(GEP->getOperand(i++));

        // Hoist base pointer as new GEP
        std::string Prefix = getPrefix(GEP);
        Value *Base = GEP->getPointerOperand();
        Value *NewBase = B.CreateInBoundsGEP(Base, ConstIdx, Prefix + "constbase");
        B.SetInsertPoint(GEP);

        // Use hoisted base pointer inside the loop
        GetElementPtrInst *NewGEP = cast<GetElementPtrInst>(B.CreateGEP(NewBase, DynIdx, Prefix + "dynamic"));
        NewGEP->setIsInBounds(GEP->isInBounds());

        DEBUG(errs() << "after split:\n");
        DEBUG(errs() << "  " << *NewBase->getType() << "  ");
        DEBUG(NewBase->dump());
        DEBUG(errs() << "  " << *NewGEP->getType() << "  ");
        DEBUG(NewGEP->dump());

        GEP->replaceAllUsesWith(NewGEP);
        GEP->eraseFromParent();

        ++NHoistedGep; // TODO use separate counter
        Changed = true;
    }
}

void SafeAllocsOld::markIntermediateExpandedInstsAsSafe(SCEVExpander &Expander, Value *Expanded) {
    ifncast(User, ExpandedU, Expanded)
        return;

    SmallVector<Instruction*, 2> Worklist;

    for (Use &U : ExpandedU->operands()) {
        ifcast(Instruction, I, U.get()) {
            if (!I->getType()->isPointerTy() && Expander.isInsertedInstruction(I) && !isSafe(I))
                Worklist.push_back(I);
        }
    }

    while (!Worklist.empty()) {
        Instruction *I = Worklist.back();
        Worklist.pop_back();
        setSafeName(I);
        SafePointers.insert(I);

        for (Use &U : I->operands()) {
            ifcast(Instruction, UI, U.get()) {
                if (Expander.isInsertedInstruction(UI) && !isSafe(UI))
                    Worklist.push_back(UI);
            }
        }
    }
}

/*
 * For GEPs inside loops, try to find the maximum possible offset and insert a
 * dummy load before the loop to do the bounds check. tag the GEP inside the
 * loop as safe to avoid arith and masking.
 */
bool SafeAllocsOld::hoistBoundCheckFromLoop(GetElementPtrInst *GEP) {
    // TODO: also do this on GEPs that have only loop invariant operands

    if (!SE->isSCEVable(GEP->getType()))
        return false;

    // GEPs in loops have a particular type of SCEV
    ifncast(const SCEVAddRecExpr, AR, SE->getSCEV(GEP))
        return false;

    // No need to hois unchecked GEPs
    if (isSafe(GEP))
        return false;

    const Loop *L = AR->getLoop();
    BasicBlock *Preheader = L->getLoopPreheader();

    // Only handle natural loops
    if (!Preheader)
        return false;

    // Can only check bound before the loop if it is guaranteed to be checked
    // inside the loop
    if (!isGuaranteedToExecuteForEveryIteration(GEP, L))
        return false;

    // Compute loop exit value
    const SCEV *ExitExpr = SE->getSCEVAtScope(AR, L->getParentLoop());
    if (!SE->isLoopInvariant(ExitExpr, L))
        return false;

    // TODO: use hasComputableLoopEvolution and isSafeToExpand

    // FIXME
    // The following check should not be necessary, but without it a bunch of
    // benchmarks crash. We should really fix this because it makes hoisting
    // much more general (see mcf for example)
    if (!L->isLoopInvariant(GEP->getPointerOperand()))
        return false;

    //DEBUG_LINE("Loop-invariant GEP exit value, move bound check before loop:");
    //DEBUG_LINE(*GEP);

    // Hoist exit pointer to preheader
    Instruction *InsertPt = Preheader->getTerminator();
    SCEVExpander Expander(*SE, *DL, "dummy_expander");
    Value *ExitValue = Expander.findExistingExpansion(ExitExpr, InsertPt, const_cast<Loop*>(L));
    if (!ExitValue)
        ExitValue = Expander.expandCodeFor(ExitExpr, nullptr, InsertPt);
    markIntermediateExpandedInstsAsSafe(Expander, ExitValue);
    std::string Prefix = GEP->hasName() ? GEP->getName().str() + "." : "";

    // Find uses of the GEP outside the loop and replace them with the (tagged)
    // dummy value so that bounds checks continue to happen after the loop
    TinyPtrVector<Instruction*> UsersOutsideLoop;
    foreach(Instruction, I, GEP->users()) {
        if (!L->contains(I))
            UsersOutsideLoop.push_back(I);
    }
    for (Instruction *I : UsersOutsideLoop) {
        DEBUG_LINE("replace user outside loop:\n");
        DEBUG_LINE(*I);
        I->replaceUsesOfWith(GEP, ExitValue);
    }

    // If the loop is not known to count up, check the entry value
    const SCEV *Step = AR->getStepRecurrence(*SE);
    if (!SE->isKnownPositive(Step)) {
        const SCEV *EntryExpr = AR->getStart();
        assert(SE->isLoopInvariant(EntryExpr, L));
        Value *EntryValue = Expander.findExistingExpansion(EntryExpr, InsertPt, const_cast<Loop*>(L));
        if (!EntryValue)
            EntryValue = Expander.expandCodeFor(EntryExpr, nullptr, InsertPt);
        markIntermediateExpandedInstsAsSafe(Expander, EntryValue);
        (new LoadInst(EntryValue, Prefix + "dummy_entry", InsertPt))->setVolatile(true);
    }

    // If the loop is not known to count down, check the exit value
    if (!SE->isKnownNegative(Step))
        (new LoadInst(ExitValue, Prefix + "dummy_exit", InsertPt))->setVolatile(true);

    // Mask the base pointer once in the preheader if possible
    Value *Base = GEP->getPointerOperand();
    if (!isSafe(Base)) {
        IRBuilder<> B(InsertPt);
        if (!L->isLoopInvariant(Base)) {
            // TODO: only mask once for each base in the same BB
            B.SetInsertPoint(GEP);
        }
        Value *MaskedBase = maskPointer(Base, B, false);
        GEP->setOperand(0, MaskedBase);
    }

    // Prevent further instrumentation inside the loop
    setSafe(GEP, Base);

    ++NHoistedGep;
    return true;
}

void SafeAllocsOld::checkArgument(Argument *Arg, bool &Changed) {
    Type *ElTy = Arg->getType()->getPointerElementType();
    if (!ElTy->isSized())
        return;
    size_t ConstSize = DL->getTypeStoreSize(ElTy);
    BoundsT PtrBounds;
    PtrBounds[Arg] = BoundT(0, static_cast<int64_t>(ConstSize));

    bool AllSafe = true;
    foreach(Instruction, UI, Arg->users()) {
        Visited.clear();
        if (isPtrUseSafe(UI, Arg, PtrBounds, MaxTraverseDepth))
            setSafe(UI, Arg);
        else
            AllSafe = false;
    }
    if (AllSafe) {
        setSafeName(Arg);
        SafePointers.insert(Arg);
        ++NArg;
    }
}

void SafeAllocsOld::checkAllocation(AllocationSite &AS, bool &Changed) {
    BoundsT PtrBounds;
    size_t ConstSize = AS.getConstSize(*DL);
    if (ConstSize != AllocationSite::NoSize)
        PtrBounds[AS.Allocation] = BoundT(0, static_cast<int64_t>(ConstSize));

    bool AllSafe = true;
    foreach(Instruction, UI, AS.Allocation->users()) {
        Visited.clear();
        if (isPtrUseSafe(UI, AS.Allocation, PtrBounds, MaxTraverseDepth))
            setSafe(UI, AS.Allocation);
        else
            AllSafe = false;
    }
    if (AllSafe) {
        setSafeName(AS.Allocation);
        SafePointers.insert(AS.Allocation);
        if (AS.isStackAllocation()) ++NStack; else ++NHeap;
    }
}

bool SafeAllocsOld::runOnModule(Module &M) {
    bool Changed = false;

    SafePointers.clear();
    PreemptedArithOffsets.clear();

    DL = &M.getDataLayout();
    TLI = &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI();
    checkGlobals(M);

    for (Function &F : M) {
        //if (F.getName() != "SetupFastFullPelSearch")
        //    continue;

        if (!shouldInstrument(F))
            continue;

        LI = &getAnalysis<LoopInfoWrapperPass>(F).getLoopInfo();
        SE = &getAnalysis<ScalarEvolutionWrapperPass>(F).getSE();

        // FIXME: this breaks other hoisting
        //hoistConstGEPOffsetsFromLoops(F, Changed);

        if (!F.hasAddressTaken()) {
            for (Argument &Arg : F.args()) {
                if (Arg.getType()->isPointerTy())
                    checkArgument(&Arg, Changed);
            }
        }

        for (inst_iterator II = inst_begin(&F), E = inst_end(&F); II != E; ++II) {
            Instruction *I = &*II;
            AllocationSite AS;

            if (isAllocation(I, AS))
                checkAllocation(AS, Changed);
        }

        for (inst_iterator II = inst_begin(&F), E = inst_end(&F); II != E; ++II) {
            Instruction *I = &*II;
            ifcast(GetElementPtrInst, GEP, I)
                Changed |= hoistBoundCheckFromLoop(GEP);
        }

        for (BasicBlock &BB : F)
            preemptBoundChecks(BB, Changed);
    }

    return Changed;
}

void SafeAllocsOld::checkGlobals(Module &M) {
    for (GlobalVariable &GV : M.globals()) {
        if (!canTagGlobal(GV))
            continue;

        Type *Ty = GV.getType()->getPointerElementType();
        assert(Ty->isSized());
        BoundsT PtrBounds;
        PtrBounds[&GV] = BoundT(0, static_cast<int64_t>(DL->getTypeStoreSize(Ty)));

        //bool AllSafe = true;
        //for (User *U : GV.users()) {
        //    ifcast(Instruction, UI, U) {
        //        Visited.clear();
        //        if (isPtrUseSafe(UI, &GV, PtrBounds, MaxTraverseDepth))
        //            setSafe(UI, &GV);
        //        else
        //            AllSafe = false;
        //    G else {
        //        AllSafe = false;
        //    }
        //}
        //if (AllSafe) {
        //    SafePointers.insert(&GV);
        //    ++NGlobal;
        //}

        Visited.clear();
        if (areAllPtrUsesSafe(&GV, PtrBounds, MaxTraverseDepth)) {
            ++NGlobal;
            if (!GV.isDeclarationForLinker() && !isNoInstrument(&GV))
                setSafeName(&GV);
            SafePointers.insert(&GV);
            for (User *U : GV.users()) {
                ifcast(Instruction, UI, U)
                    setSafe(UI, &GV);
            }
        }
    }
    // TODO: set changed flag
}

static unsigned firstDeref(const Instruction *Ptr) {
    int Idx = 0;
    for (const Instruction &I : *Ptr->getParent()) {
        if (isa<LoadInst>(&I)) {
            return Idx;
        }
        else ifcast(const StoreInst, SI, &I) {
            if (SI->getPointerOperand() == Ptr)
                return Idx;
        }
        Idx++;
    }
    errs() << "gep is never dereferenced (func " << Ptr->getParent()->getParent()->getName() << "):\n";
    Ptr->dump();
    assert(false);
    return 0;
}

static bool isOnlyUsedAndDereferencedInBlock(Instruction *I, BasicBlock *BB) {
    for (User *U : I->users()) {
        if (cast<Instruction>(U)->getParent() != BB) {
            return false;
        }
        else ifcast(StoreInst, SI, U) {
            if (SI->getValueOperand() == I)
                return false;
        }
        else if (!isa<LoadInst>(U)) {
            return false;
        }
    }
    return true;
}

/*
 * For constant GEPs in the same basic block that reference the same base
 * pointer, only the maximum offset needs to be checked. Add this offset to the
 * first dereferenced pointer and mark the rest as safe.
 */
void SafeAllocsOld::preemptBoundChecks(BasicBlock &BB, bool &Changed) {
    // Find all remaining unsafe constant GEPS that are only used inside the
    // block, grouping them by base pointer
    DenseMap<Value*, SmallVector<GetElementPtrInst*, 2>> InternalGEPs;
    for (Instruction &I : BB) {
        ifncast(GetElementPtrInst, GEP, &I)
            continue;
        if (isSafe(GEP))
            continue;
        if (!GEP->hasAllConstantIndices())
            continue;
        if (!isOnlyUsedAndDereferencedInBlock(GEP, &BB))
            continue;
        InternalGEPs.FindAndConstruct(GEP->getPointerOperand()).second.push_back(GEP);
    }

    IRBuilder<> B(BB.getContext());

    for (auto P : InternalGEPs) {
        Value *Base = P.first;
        SmallVector<GetElementPtrInst*, 2> &GEPs = P.second;

        // Only consider each base pointer that have multiple uses in the block
        if (GEPs.size() < 3)
            continue;

        // Set the insert point before sorting to make sure the masked base
        // will dominate all uses
        B.SetInsertPoint(GEPs[0]);

        // Sort the GEPs in the order in which they are dereferenced
        std::sort(GEPs.begin(), GEPs.end(),
                [](const GetElementPtrInst *A, const GetElementPtrInst *B) {
                    return firstDeref(A) < firstDeref(B);
                });

        // Find the maximum offset
        GetElementPtrInst *MaxOffsetGEP = GEPs[0];
        APInt MaxOffset(PointerBits, 0);
        GEPs[0]->accumulateConstantOffset(*DL, MaxOffset);

        for (unsigned i = 1, n = GEPs.size(); i < n; ++i) {
            APInt Offset(PointerBits, 0);
            GEPs[i]->accumulateConstantOffset(*DL, Offset);
            if (Offset.sgt(MaxOffset)) {
                MaxOffset = Offset;
                MaxOffsetGEP = GEPs[i];
            }
        }

        // Set the maximum offset on the first GEP
        assert(PreemptedArithOffsets.lookup(GEPs[0]) == nullptr);
        PreemptedArithOffsets[GEPs[0]] = MaxOffsetGEP;

        // Tag the other GEPs as safe and mask the base pointer
        Value *SafeBase = nullptr;
        if (!isSafe(Base)) {
            SafeBase = maskPointer(Base, B, false);
            Changed = true;
        }
        for (unsigned i = 1, n = GEPs.size(); i < n; ++i) {
            if (SafeBase)
                GEPs[i]->setOperand(0, SafeBase);
            setSafe(GEPs[i], Base);
        }

        NPreemptedChecks += GEPs.size() - 1;

        //DEBUG_LINE("Preempt max offset check " << MaxOffset.getSExtValue() <<
        //           " out of " << GEPs.size() << " GEPs in " <<
        //           BB.getParent()->getName() << ":" << BB.getName() << ":");
        //DEBUG_LINE(*GEPs[0]);
    }
}

/*
bool SafeAllocsOld::hasPreemptedOffset(GetElementPtrInst *GEP, int64_t &Offset) {
    auto it = PreemptedArithOffsets.find(GEP);
    if (it == PreemptedArithOffsets.end())
        return false;
    Offset = it->second;
    return true;
}
*/

Value *SafeAllocsOld::maskPointer(Value *Ptr, IRBuilder<> &B, bool MayPreserveOverflowBit) {
    std::string Prefix = Ptr->hasName() ? Ptr->getName().str() + "." : "";
    Value *PtrInt = B.CreatePtrToInt(Ptr, getPtrIntTy(Ptr->getContext()), Prefix + "int");
    Value *Mask = B.CreateAnd(PtrInt, getAddressSpaceMask(MayPreserveOverflowBit), Prefix + "mask");
    Value *Masked = B.CreateIntToPtr(Mask, cast<PointerType>(Ptr->getType()), Prefix + "masked");
    SafePointers.insert(Masked);
    return Masked;
}
