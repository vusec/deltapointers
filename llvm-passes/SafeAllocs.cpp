#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/Analysis/ScalarEvolutionExpander.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/ADT/TinyPtrVector.h>
#include <llvm/IR/NoFolder.h>
#include <llvm/IR/Dominators.h>

#include <initializer_list>

#define DEBUG_TYPE "safe-allocs"

/*
 * This is an experimental/unfinished implementiaton of optimizations based on
 * Scalar Evolution (SCEV). It is not actually used by default, but can be
 * enabled by modifying instances.py.
 */

#include "utils/Common.h"
#include "utils/CustomFunctionPass.h"
#include "utils/Allocation.h"
#include "AddressSpace.h"
#include "TagGlobalsConst.h"
#include "SafeAllocs.h"
#include "LibPtrRet.h"

using namespace llvm;

char SafeAllocs::ID = 0;
static RegisterPass<SafeAllocs> X("safe-allocs",
        "Analyze object bounds to avoid instrumentation on 'safe' allocations, GEPs and dereferences",
        false, true);

enum Options : unsigned { global, stack, heap, arith, propagate, preempt };

static cl::bits<enum Options> Options("safe-allocs-enable",
        cl::desc("Enable options for safe-allocs pass (default all):"),
        cl::values(
            clEnumVal(global,    "Find safe globals (avoid global tagging)"),
            clEnumVal(stack,     "Find safe stack allocations (avoid alloca tagging)"),
            clEnumVal(heap,      "Find safe heap allocations (avoid malloc tagging)"),
            clEnumVal(arith,     "Find safe pointer arithmetic instructions (avoid GEP instrumentation)"),
            clEnumVal(propagate, "Propagate safe tags to user pointers (avoid load/store/libcall masks)"),
            clEnumVal(preempt,   "Preempt bounds checks on GEPS of the same base pointer in the same basic block (avoid GEP instrumentation)"),
            clEnumValEnd));

// TODO: have a command line option to trust library functions not to do out of
// bounds stuff with pointers, just check if the pointer itself is not out of
// bounds at the libcall (i.e., treat them as a load/store)

STATISTIC(NSafeGEPs,         "Number of safe GEPs (total)");
STATISTIC(NSafeGEPsGlobal,   "Number of safe GEPs (global)");
STATISTIC(NSafeGEPsStack,    "Number of safe GEPs (stack)");
STATISTIC(NSafeGEPsHeap,     "Number of safe GEPs (heap)");
STATISTIC(NSafeGEPsUnknown,  "Number of safe GEPs (unknown)");
STATISTIC(NSafeGEPsProp,     "Number of safe GEPs (propagated)");
STATISTIC(NIgnoredLoopIters, "Number of ignored last loop iterations when checking GEP bounds");

STATISTIC(NSafeAllocs,       "Number of safe allocations (total)");
STATISTIC(NSafeAllocsGlobal, "Number of safe allocations (global)");
STATISTIC(NSafeAllocsStack,  "Number of safe allocations (stack)");
STATISTIC(NSafeAllocsHeap,   "Number of safe allocations (heap)");

STATISTIC(NSafeDerefs,       "Number of safe loads/stores (total)");
STATISTIC(NSafeDerefsGlobal, "Number of safe loads/stores (global)");
STATISTIC(NSafeDerefsStack,  "Number of safe loads/stores (stack)");
STATISTIC(NSafeDerefsHeap,   "Number of safe loads/stores (heap)");
STATISTIC(NSafeDerefsUnknown,"Number of safe loads/stores (unknown)");
STATISTIC(NSafeLibCallArgs,  "Number of safe libcall arguments");

STATISTIC(NPreemptedOffsets, "Number of preempted bound checks");
STATISTIC(NSafeGEPsPreempt,  "Number of safe GEPs (preemption)");

void SafeAllocs::getAnalysisUsage(AnalysisUsage &AU) const {
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<LoopInfoWrapperPass>();
    AU.addRequired<ScalarEvolutionWrapperPass>();
    AU.setPreservesAll();
}

bool SafeAllocs::needsTag(Value *Allocation) {
    return !SafeAllocations.count(Allocation);
}

bool SafeAllocs::needsMask(Instruction *I, Value *Operand) {
    return !SafeMaskSites.count(std::make_pair(I, Operand));
}

bool SafeAllocs::needsPropagation(GetElementPtrInst *GEP) {
    return !SafeGEPs.count(GEP);
}

GetElementPtrInst *SafeAllocs::getPreemptedOffset(GetElementPtrInst *GEP) {
    return PreemptedArithOffsets.lookup(GEP);
}

static void setSafeName(Value *V) {
    // Void values can not have a name
    if (V->getType()->isVoidTy())
        return;

    // Don't corrupt externally visable symbols
    GlobalValue *GV = dyn_cast<GlobalValue>(V);
    if (GV && GV->isDeclarationForLinker())
        return;

    // Don't name values that are not globals or instructions
    if (!GV && !isa<Instruction>(V))
        return;

    // Add name to anonymous instructions
    if (!V->hasName()) {
        V->setName("safe.anon");
        return;
    }

    // Don't corrupt llvm.* names
    if (V->getName().startswith("llvm."))
        return;

    // Don't rename twice
    if (V->getName().startswith("safe."))
        return;

    // Default: prefix name with "safe."
    V->setName(Twine("safe.") + V->getName());
}

void SafeAllocs::setNoTag(Value *Allocation) {
    SafeAllocations.insert(Allocation);
    setSafeName(Allocation);
}

void SafeAllocs::setNoMask(Instruction *I, Value *Operand) {
    SafeMaskSites.insert(std::make_pair(I, Operand));
    setSafeName(Operand);
}

void SafeAllocs::setNoPropagation(GetElementPtrInst *GEP) {
    SafeGEPs.insert(GEP);
    setSafeName(GEP);
}

void SafeAllocs::setPreemptedOffset(GetElementPtrInst *CheckGEP,
        GetElementPtrInst *OffsetGEP) {
    assert(getPreemptedOffset(CheckGEP) == nullptr);
    PreemptedArithOffsets[CheckGEP] = OffsetGEP;

    if (CheckGEP->hasName() && OffsetGEP->hasName())
        CheckGEP->setName(CheckGEP->getName() + Twine(".offsetof.") + OffsetGEP->getName());
    else if (OffsetGEP->hasName())
        CheckGEP->setName(Twine("anon.offsetof.") + OffsetGEP->getName());
    else if (CheckGEP->hasName())
        CheckGEP->setName(CheckGEP->getName() + Twine(".offsetof.anon"));
    else
        CheckGEP->setName("anon.offsetof.anon");
}

bool SafeAllocs::runOnModule(Module &M) {
    // Enable all optimizations by default, if none are explicitly enabled
    if (Options.getNumOccurrences() == 0) {
        Options.addValue(global);
        Options.addValue(stack);
        Options.addValue(heap);
        Options.addValue(arith);
        Options.addValue(propagate);
        Options.addValue(preempt);
    }

    SafeAllocations.clear();
    SafeGEPs.clear();
    SafeMaskSites.clear();
    PreemptedArithOffsets.clear();

    DL = &M.getDataLayout();

    DenseMap<Value*, const SCEV*> PointerBounds;

    for (Function &F : M) {
        if (!shouldInstrument(F))
            continue;

        DT = &getAnalysis<DominatorTreeWrapperPass>(F).getDomTree();
        LI = &getAnalysis<LoopInfoWrapperPass>(F).getLoopInfo();
        SE = &getAnalysis<ScalarEvolutionWrapperPass>(F).getSE();

        // TODO: find trivially safe pointers in function arguments
        // TODO: use getDereferenceableBytes

        // Find safe GEP instructions
        if (Options.isSet(arith)) {
            PointerBounds.clear();
            propagateAllocationBounds(F, PointerBounds);
            findSafeGEPs(F, PointerBounds);
        }

        // Find safe stack/heap allocations to avoid tagging
        if (Options.isSet(stack) || Options.isSet(heap))
            findSafeAllocations(F);

        // Preempt bound checks by setting the metadata offset of a GEP to the
        // highest offset of the base pointer in the same basic block
        if (Options.isSet(preempt))
            preemptBoundChecks(F);
    }

    // Find safe global allocations to avoid tagging
    if (Options.isSet(global))
        findSafeGlobals(M);

    // Propagate safe status from allocations/geps to loads/stores and libcalls
    // to avoid masking
    if (Options.isSet(propagate))
        propagateSafeTags();

    return false;
}

/*
 * Starting from globals / allocation insts, propagate the distance to the end
 * of the object as a SCEV expression to subsequent pointer arithmetic.
 */
void SafeAllocs::propagateAllocationBounds(Function &F,
        DenseMap<Value*, const SCEV*> &PointerBounds) {
    SmallVector<std::pair<Instruction*, const SCEV*>, 16> Worklist;

    // TODO: propagate argument type bounds (?)

    for (Instruction &I : instructions(F)) {
        AllocationSite AS;
        if (isAllocation(&I, AS)) {
            Worklist.push_back(std::make_pair(&I, AS.getSizeSCEV(*SE)));
        }
        else if (I.getNumOperands() > 0) {
            ifncast(GlobalVariable, GV, I.getOperand(0))
                continue;

            const SCEV *Size = getGlobalSizeSCEV(GV, *SE);

            switch (I.getOpcode()) {
                case Instruction::BitCast:
                case Instruction::PtrToInt:
                case Instruction::IntToPtr:
                    Worklist.push_back(std::make_pair(&I, Size));
                    break;
                case Instruction::GetElementPtr:
                    Worklist.push_back(std::make_pair(&I, SE->getMinusSCEV(Size,
                                    getGEPOffsetSCEV(cast<GetElementPtrInst>(&I)))));
                    break;
                case Instruction::Call:
                case Instruction::Invoke:
                    // TODO: use libptrret info
                    break;
                default:
                    break;
            }
        }
    }

    while (!Worklist.empty()) {
        const auto &P = Worklist.pop_back_val();
        Instruction *I = P.first;
        const SCEV *Dist = P.second;

        assert(PointerBounds.count(I) == 0);
        PointerBounds[I] = Dist;

        for (User *U : I->users()) {
            Instruction *UI = cast<Instruction>(U);
            const SCEV *UDist = nullptr;

            switch (UI->getOpcode()) {
                case Instruction::Call:
                case Instruction::Invoke:
                    // TODO: use libptrret info
                    break;
                case Instruction::ICmp:
                case Instruction::Load:
                case Instruction::Store:
                case Instruction::Ret:
                    // Ignored
                    break;
                default:
                    if (const SCEV *Offset = getPointerCastOrArithOffset(UI, I)) {
                        UDist = Offset->isZero() ? Dist : SE->getMinusSCEV(Dist, Offset);
                        break;
                    }
                    // TODO: check these in log files
                    DEBUG_LINE("unsupported:" << *UI);
                    DEBUG_LINE("       uses:" << *I);
                    //assert(false);
                    break;
            }

            if (UDist)
                Worklist.push_back(std::make_pair(UI, UDist));
        }
    }
}

void SafeAllocs::findSafeGEPs(Function &F,
        DenseMap<Value*, const SCEV*> &PointerBounds) {
    for (Instruction &I : instructions(F)) {
        ifncast(GetElementPtrInst, GEP, &I)
            continue;

        // See if the distance to the end of the object was propagated by
        // propagateAllocationBounds.
        auto it = PointerBounds.find(GEP);
        if (it == PointerBounds.end())
            continue;
        const SCEV *Distance = it->second;

        DEBUG_LINE("gep:      " << *GEP);
        DEBUG_LINE("distance: " << *Distance);

        // Some GEPs in loops use the induction variable, causing SCEV analysis
        // to think that the maximum value of the pointer is the value *after*
        // the loop, which is usually a pointer to the end of the object (which
        // is OOB). We detect the pattern where the induction variable is
        // compared to a loop exit value before ever being dereferenced, and
        // ignore the last iteration in the distance calculation.
        //   TODO: it may be better to use evaluateAtIteration icw
        //   getBackedgeTakenCount instead of the phi step stuff (
        InductionDescriptor D;
        if (isNotDereferencedInLastLoopIteration(GEP, D)) {
            if (D.getConsecutiveDirection() == 1) {
                // i += step
                const SCEV *Step = SE->getConstant(D.getStepValue());
                Distance = SE->getAddExpr(Distance, Step);
                DEBUG_LINE("ignore last iteration, new distance: " << *Distance);
                NIgnoredLoopIters++;
            }
            else if (D.getConsecutiveDirection() == -1) {
                // i -= step
                // XXX: not sure what to do here, check the first iteration only?
            }
        }

        // For a GEP in an incrementing for-loop, we only need to check the
        // value after (or in, see above) the last iteration. Note that an
        // incrementing loop implies a decrementing distance, hence the
        // isKnownNegative check.
        // Similarly, we only look at the first iteration for decrementing
        // loops
        ifcast(const SCEVAddRecExpr, AR, Distance) {
            if (SE->isKnownNegative(AR->getStepRecurrence(*SE))) {
                Distance = SE->getSCEVAtScope(AR, AR->getLoop()->getParentLoop());
                DEBUG_LINE("max distance in loop: " << *Distance);
            }
            else if (SE->isKnownPositive(AR->getStepRecurrence(*SE))) {
                // TODO: get value at first iteration
                DEBUG_LINE("max distance in loop: " << *Distance);
            }
        }

        // We need to statically prove that the distance is larger than the
        // maximum dereferenced number of bytes from this pointer. So, we
        // traverse the uses until we find dereferences (load/store/memset/etc)
        // and accumulate the dereferenced byte ranges for static bounds
        // checks by SCEV.
        if (!isNotDereferencedBeyondNBytes(GEP, Distance))
            continue;

        DEBUG_LINE("safe GEP!:" << *GEP);
        setNoPropagation(GEP);

        // Update statistic counters
        NSafeGEPs++;

        Value *Base = GEP->getPointerOperand()->stripInBoundsOffsets();
        AllocationSite AS;

        if (isa<GlobalVariable>(Base)) {
            NSafeGEPsGlobal++;
        }
        else if (isAllocation(cast<Instruction>(Base), AS)) {
            if (AS.isStackAllocation())
                NSafeGEPsStack++;
            else
                NSafeGEPsHeap++;
        }
        else {
            NSafeGEPsUnknown++;
        }
    }
}

void SafeAllocs::findSafeAllocations(Function &F) {
    AllocationSite AS;

    for (Instruction &I : instructions(F)) {
        if (!isAllocation(&I, AS))
            continue;

        if (!Options.isSet(stack) && AS.isStackAllocation())
            continue;

        if (!Options.isSet(heap) && AS.isHeapAllocation())
            continue;

        if (!isNotDereferencedBeyondNBytes(&I, AS.getSizeSCEV(*SE)))
            continue;

        setNoTag(&I);

        // Update statistic counters
        NSafeAllocs++;

        if (AS.isStackAllocation()) {
            DEBUG_LINE("safe stack allocation:" << I);
            NSafeAllocsStack++;
        } else {
            DEBUG_LINE("safe heap allocation:" << I);
            NSafeAllocsHeap++;
        }
    }
}

static bool instUsesInst(Instruction *I, Instruction *Needle) {
    SmallVector<Instruction*, 8> Worklist;
    SmallPtrSet<Instruction*, 8> Visited;
    Worklist.push_back(I);

    do {
        I = Worklist.pop_back_val();

        if (I == Needle)
            return true;

        if (!Visited.insert(I).second)
            continue;

        for (Use &U : I->operands()) {
            ifcast(Instruction, UI, U.get())
                Worklist.push_back(UI);
        }
    } while (!Worklist.empty());

    return false;
}

void SafeAllocs::preemptBoundChecks(Function &F) {
    DenseMap<Value*, SmallVector<GetElementPtrInst*, 4>> BaseGEPs;
    SmallVector<SmallVector<GetElementPtrInst*, 4>, 4> Groups;

    //DEBUG_LINE("hi, preempt " << F.getName());

    for (BasicBlock &BB : F) {
        // TODO: also consider bitcasts, insert zero-geps in that case

        // We are looking for GEPs that are only used once by a load/store, in
        // the other in which they are dereferenced (so that we know which one
        // to move the check to when merging). Note that the GEPs need not
        // even be in the same basic block, we use dominator information later
        // on to move instructions necessary for offset calculation to the
        // first dereferemced GEP.
        BaseGEPs.clear();
        for (Instruction &I : BB) {
            GetElementPtrInst *GEP;
            ifcast(LoadInst, LI, &I)
                GEP = dyn_cast<GetElementPtrInst>(LI->getPointerOperand());
            else ifcast(StoreInst, SI, &I)
                GEP = dyn_cast<GetElementPtrInst>(SI->getPointerOperand());
            else
                continue;

            if (!GEP || GEP->getNumUses() != 1)
                continue;

            // Skip already safe GEPs
            if (!needsPropagation(GEP))
                continue;

            Value *Base = GEP->getPointerOperand()->stripPointerCasts();
            BaseGEPs.FindAndConstruct(Base).second.push_back(GEP);
        }

        // For each base pointer, divide the GEPs into groups that can be
        // compared to each other
        for (auto it : BaseGEPs) {
            //Value *Base = it.first;
            SmallVectorImpl<GetElementPtrInst*> &GEPs = it.second;
            Groups.clear();

            //DEBUG_LINE("base: " << *it.first);

            // Append a GEP to the first group that has a member that has a
            // comparable SCEV
            for (GetElementPtrInst *GEP : GEPs) {
                //DEBUG_LINE(" gep:" << *GEP);
                //DEBUG_LINE(" scev: " << *SE->getSCEV(GEP));
                bool Found = false;

                unsigned i = 0;
                for (SmallVectorImpl<GetElementPtrInst*> &Group : Groups) {
                    //DEBUG_LINE(" group " << i);
                    for (GetElementPtrInst *Other : Group) {
                        //DEBUG_LINE(" other scev: " << *SE->getSCEV(Other));
                        // It does not matter how the SCEVs compare, as long as
                        // they are comparable, so that we can find the maximum
                        // later
                        // FIXME: maybe we should just compare to the first
                        // element

                        // The earlier GEP should not be used in the offset
                        // calculation, not should its loaded value, since then
                        // the offset calculation can not be moved up.

                        // E.g.:
                        //   %other = gep %base, ...
                        //   %otheri = bitcast %other to i64
                        //   %off = sub %otheri, %base
                        //   %gep = gep %base, %off, ...
                        if (instUsesInst(GEP, Other))
                            continue;

                        // E.g.:
                        //   %other = gep %base, ...
                        //   %off = load %other
                        //   %gep = gep %base, %off, ...
                        ifcast(LoadInst, LI, getSingleUser<Instruction>(Other)) {
                            if (instUsesInst(GEP, LI))
                                continue;
                        }

                        // The instructions must be part of the same inner loop
                        // as well
                        BasicBlock *GEPB = GEP->getParent(), *OtherB = Other->getParent();
                        if (GEPB != OtherB && LI->getLoopFor(GEPB) != LI->getLoopFor(OtherB))
                            continue;

                        if (compareGEPs(ICmpInst::ICMP_SLE, GEP, Other) ||
                            compareGEPs(ICmpInst::ICMP_SGT, GEP, Other)) {
                            Group.push_back(GEP);
                            //DEBUG_LINE(" found");
                            Found = true;
                            // TODO: assert that rest of the group is also comparable?
                            break;
                        }
                    }
                    if (Found)
                        break;
                    i++;
                }

                // Create a new group if no existing group was comparable
                if (!Found) {
                    Groups.emplace_back(std::initializer_list<GetElementPtrInst*>{GEP});
                    //DEBUG_LINE(" new group");
                }
            }

            // At this point, all groups with > 1 members can be merged into
            // the first dereferenced (which is the first element of the group,
            // by order of processing)
            for (SmallVectorImpl<GetElementPtrInst*> &Group : Groups) {
                if (Group.size() < 2)
                    continue;

                // Find the GEP with the maximum offset
                GetElementPtrInst *CheckGEP = Group[0];
                GetElementPtrInst *MaxGEP = CheckGEP;

                for (auto I = std::next(Group.begin()), E = Group.end(); I != E; ++I) {
                    GetElementPtrInst *GEP = *I;
                    if (compareGEPs(ICmpInst::ICMP_SGT, GEP, MaxGEP))
                        MaxGEP = GEP;
                }

                // Inform deltatagsprop pass to copy the offset of the maximum
                // GEP to the first dereferenced GEP
                if (MaxGEP != CheckGEP) {
                    setPreemptedOffset(CheckGEP, MaxGEP);
                    DEBUG_LINE("preempted " << (Group.size() - 1) <<
                               " propagations in " << F.getName() << ":");
                    DEBUG_LINE("  check: " << *CheckGEP);
                    DEBUG_LINE("  offset:" << *MaxGEP);
                }

                NPreemptedOffsets++;

                // Tag all the other GEPs in the group as safe to avoid
                // instrumentation
                for (auto I = std::next(Group.begin()), E = Group.end(); I != E; ++I) {
                    GetElementPtrInst *GEP = *I;
                    setNoPropagation(GEP);
                    // TODO: also remove mask from load/store

                    NSafeGEPs++;
                    NSafeGEPsPreempt++;
                }
            }
        }
    }
}

void SafeAllocs::findSafeGlobals(Module &M) {
    for (GlobalVariable &GV : M.globals()) {
        if (!isNotDereferencedBeyondNBytes(&GV, getGlobalSizeSCEV(&GV, *SE)))
            continue;

        DEBUG_LINE("safe global:" << GV);
        setNoTag(&GV);

        // Update statistic counters
        NSafeAllocs++;
        NSafeAllocsGlobal++;
    }
}

static bool libCallReturnsSameObjectPointer(CallSite &CS, Value *Param) {
    Function *F = CS.getCalledFunction();
    assert(F);
    assert(F->isDeclaration());

    int Arg;
    switch (getLibPtrType(F, &Arg)) {
        case LibPtr::Strtok:
        case LibPtr::CopyFromArg:
        case LibPtr::PtrDiff:
            return CS.getArgOperand(Arg) == Param;
        default:
            return false;
    }

    return false;
}

void SafeAllocs::propagateSafeTags() {
    SmallVector<std::pair<Instruction*, Value*>, 32> Worklist;

    DEBUG_LINE("propagate safe tags");

    // Only propagate from safe allocations, we cannot propagate from safe GEPs
    // that can not be traced back to a safe allocation, since those pointers
    // may have metadata
    for (Value *Alloc : SafeAllocations) {
        for (User *U : Alloc->users()) {
            ifncast(Instruction, UI, U)
                continue;

            // No propagation should have happened yet
            assert(hasTag(UI));

            Worklist.push_back(std::make_pair(UI, Alloc));
        }
    }

    DenseSet<std::pair<Instruction*, Value*>> VisitedPHINodes;

    while (!Worklist.empty()) {
        const auto &it = Worklist.pop_back_val();
        Instruction *UI = it.first;
        Value *Ptr = it.second;

        // Depending on the type of user, tag it as safe and/or stop
        // propagation
        switch (UI->getOpcode()) {
            case Instruction::Load:
            case Instruction::Store: {
                // Prevent load/store masking
                setNoMask(UI, Ptr);
                NSafeDerefs++;

                AllocationSite AS;
                Value *Base = Ptr->stripInBoundsOffsets();
                if (isa<GlobalVariable>(Base)) {
                    NSafeDerefsGlobal++;
                }
                else if (isAllocation(cast<Instruction>(Base), AS)) {
                    if (AS.isStackAllocation())
                        NSafeDerefsStack++;
                    else
                        NSafeDerefsHeap++;
                }
                else {
                    NSafeDerefsUnknown++;
                }

                continue;
            }
            case Instruction::GetElementPtr:
                NSafeGEPs++;
                NSafeGEPsProp++;
                /* fall through */
            case Instruction::BitCast:
            case Instruction::IntToPtr:
            case Instruction::PtrToInt:
                // Propagate the information that this pointer does not have
                // metadata, this will be used when propagating from safe GEPs
                setNoTag(UI);
                break;
            case Instruction::Call:
            case Instruction::Invoke: {
                // Prevent libcall argument masking
                if (needsMask(UI, Ptr)) {
                    setNoMask(UI, Ptr);
                    NSafeLibCallArgs++;
                }

                // Avoid copying the tag to the return value
                CallSite CS(UI);
                Function *F = CS.getCalledFunction();
                if (F && F->isDeclaration() && libCallReturnsSameObjectPointer(CS, Ptr)) {
                    setNoTag(UI);
                    // Continue propagation
                    break;
                }

                // Stop propagation
                continue;
            }
            case Instruction::PHI: {
                // Check if all incoming values are safe
                bool allSafe = true;
                PHINode *PN = cast<PHINode>(UI);
                for (Use &U : PN->operands()) {
                    if (hasTag(PN->getIncomingValueForBlock(PN->getIncomingBlock(U)))) {
                        allSafe = false;
                        break;
                    }
                }
                if (!allSafe) {
                    VisitedPHINodes.insert(it);
                    continue;
                }

                setNoTag(UI);
                break;
            }
            default:
                // TODO: add/sub
                DEBUG_LINE("unsupported for propagation:" << *UI);
                continue;
        }

        // Recurse to users
        for (User *UU : UI->users()) {
            auto P = std::make_pair(cast<Instruction>(UU), UI);
            if (hasTag(UU) && !VisitedPHINodes.count(P))
                Worklist.push_back(P);
        }
    }
}

bool SafeAllocs::isNotDereferencedBeyondNBytes(Value *Ptr,
        const SCEV *DistanceToEndOfObject) {
    SmallVector<const SCEV*, 8> DerefBytes;

    if (!findAllDereferencedBytes(Ptr, DerefBytes))
        return false;

    for (const SCEV *NBytes : DerefBytes) {
        if (!compareSCEVs(ICmpInst::ICMP_SGE, DistanceToEndOfObject, NBytes))
            return false;

        DEBUG_LINE("distance " << *DistanceToEndOfObject << " >= nbytes " << *NBytes);
    }

    return true;
}

/*
 * Collect SCEVs of all instructions that dereference a given pointer.
 */
bool SafeAllocs::findAllDereferencedBytes(Value *Ptr,
        SmallVectorImpl<const SCEV*> &DerefBytes) {
    struct Entry {
        Value *I;
        Instruction *UI;
        const SCEV *Offset;
    };

    SmallVector<struct Entry, 8> Worklist;
    SmallPtrSet<PHINode*, 4> VisitedPHINodes;

    for (User *U : Ptr->users()) {
        ifcast(Instruction, UI, U)
            Worklist.push_back({ Ptr, UI, nullptr });
    }

    while (!Worklist.empty()) {
        const struct Entry &E = Worklist.pop_back_val();
        const SCEV *UOffset = E.Offset;

        switch (E.UI->getOpcode()) {
            case Instruction::Load:
                // Add the number of bytes loaded, do not look at users
                DerefBytes.push_back(addSCEVs(E.Offset, getSizeOfSCEV(E.UI->getType())));
                continue;
            case Instruction::Store:
                // Give up tracking if the pointer value is stored in memory
                if (E.UI->getOperand(0) == E.I)
                    return false;
                // Add the number of bytes stored
                DerefBytes.push_back(addSCEVs(E.Offset, getSizeOfSCEV(E.UI->getOperand(0)->getType())));
                continue;
            case Instruction::PHI:
                // Avoid recursing cyclic phi references
                if (VisitedPHINodes.count(cast<PHINode>(E.UI)))
                    continue;
                VisitedPHINodes.insert(cast<PHINode>(E.UI));
                break;
            case Instruction::Call:
            case Instruction::Invoke:
                // TODO: support safe calls that do not dereference memory (use
                // targetlibinfo maybe?)
                return false;

            // TODO: MemIntrinsic

            case Instruction::GetElementPtr:
                // Break  on safe GEPs since they are already proven to only
                // dereference inbounds (fallthrough to the check otherwise)
                if (!needsPropagation(cast<GetElementPtrInst>(E.UI)))
                    continue;
                /* fall through */
            default:
                if (const SCEV *PtrOffset = getPointerCastOrArithOffset(E.UI, E.I)) {
                    if (PtrOffset->isZero()) {
                        // Follow pointer casts
                    } else {
                        UOffset = addSCEVs(UOffset, PtrOffset);
                    }
                    break;
                }

                DEBUG_LINE("unsupported for tracking:" << *E.UI);
                DEBUG_LINE("                      of:" << *E.I);
                return false;
        }

        for (User *U : E.UI->users())
            Worklist.push_back({ E.UI, cast<Instruction>(U), UOffset });
    }

    return true;
}

static Value *getComparedLoopExitValue(const Loop *L, Value *V, BranchInst *&Br) {
    if (!L->hasDedicatedExits())
        return nullptr;

    Br = dyn_cast<BranchInst>(L->getHeader()->getTerminator());

    if (!Br || Br->isUnconditional())
        return nullptr;

    ifncast(ICmpInst, Cmp, Br->getCondition())
        return nullptr;

    if (Cmp->getPredicate() != ICmpInst::ICMP_EQ)
        return nullptr;

    if (L->contains(Br->getSuccessor(0)) || !L->contains(Br->getSuccessor(1)))
        return nullptr;

    if (Cmp->getOperand(0) == V)
        return Cmp->getOperand(1);
    else if (Cmp->getOperand(1) == V)
        return Cmp->getOperand(0);

    return nullptr;
}

bool SafeAllocs::isNotDereferencedInLastLoopIteration(
        GetElementPtrInst *GEP, InductionDescriptor &D) {
    // If the pointer is a GEP in a loop ...
    const SCEV *SC = SE->getSCEV(GEP);

    ifncast(const SCEVAddRecExpr, AR, SC)
        return false;

    const Loop *L = AR->getLoop();

    // ... and all users are loads/stores within the loop ...
    SmallVector<Instruction*, 4> Derefs;
    for (User *U : GEP->users()) {
        ifcast(LoadInst, LI, U) {
            Derefs.push_back(LI);
        }
        else ifcast(StoreInst, SI, U) {
            if (SI->getValueOperand() == GEP)
                return false;
            Derefs.push_back(LI);
        }
        else {
            return false;
        }
    }

    // ... and it is based on the loop induction variable ...
    if (GEP->getNumOperands() != 2)
        return false;

    ifncast(PHINode, PN, GEP->getOperand(1))
        return false;

    assert(AR->getLoop()->getLoopPreheader());
    if (!InductionDescriptor::isInductionPHI(PN, SE, D))
        return false;

    // ... which determines the exit condition of the loop ...
    BranchInst *Br;
    Value *ComparedExitValue = getComparedLoopExitValue(L, PN, Br);
    if (!ComparedExitValue)
        return false;

    const SCEV *ExitExpr = SE->getSCEVAtScope(AR, L->getParentLoop());
    assert(SE->hasOperand(ExitExpr, SE->getSCEV(ComparedExitValue)));

    // ... and the branch dominates all loads/stores ...
    for (Instruction *Deref : Derefs) {
        if (!DT->dominates(Br, Deref)) {
            DEBUG_LINE("not dominated:" << *Deref);
            DEBUG_LINE("           by:" << *Br);
            return false;
        }
    }

    // ... then the pointer is never dereferenced in the last iteration
    return true;
}

const SCEV *SafeAllocs::addNoWrapFlags(const SCEV *V) {
    // TODO: if we don't need this, remove it

    // FIXME: this appears to make stuff persistent even if you call
    // forgetValue (?)
    SmallVector<const SCEV*, 3> Ops;

    ifcast(const SCEVNAryExpr, NAry, V) {
        for (const SCEV *Op : NAry->operands())
            Ops.push_back(addNoWrapFlags(Op));
    }
    else ifcast(const SCEVCastExpr, Cast, V) {
        Ops.push_back(addNoWrapFlags(Cast->getOperand()));
    }
    else ifcast(const SCEVUDivExpr, UDiv, V) {
        Ops.push_back(addNoWrapFlags(UDiv->getLHS()));
        Ops.push_back(addNoWrapFlags(UDiv->getRHS()));
    }

    //SCEV::NoWrapFlags Flags = ScalarEvolution::setFlags(SCEV::FlagNUW, SCEV::FlagNSW);
    SCEV::NoWrapFlags Flags = SCEV::FlagNSW;

    switch (static_cast<SCEVTypes>(V->getSCEVType())) {
        case scAddExpr:
            return SE->getAddExpr(Ops, Flags);
        case scMulExpr:
            return SE->getMulExpr(Ops, Flags);
        case scUDivExpr:
            return SE->getUDivExpr(Ops[0], Ops[1]);
        case scAddRecExpr:
            return SE->getAddRecExpr(Ops, cast<SCEVAddRecExpr>(V)->getLoop(), Flags);
        case scSignExtend:
            return SE->getSignExtendExpr(Ops[0], V->getType());
        case scZeroExtend:
            return SE->getZeroExtendExpr(Ops[0], V->getType());
        case scTruncate:
            return SE->getTruncateExpr(Ops[0], V->getType());
        case scConstant:
        case scUnknown:
        case scSMaxExpr:
        case scUMaxExpr:
        case scCouldNotCompute:
            return V;
    }

    llvm_unreachable("broken out of covered switch");
}

const SCEV *SafeAllocs::getGEPOffsetSCEV(GetElementPtrInst *GEP, bool NoWrap) {
    Value *Base = GEP->getPointerOperand();
    const SCEV *Offset = SE->getMinusSCEV(SE->getSCEV(GEP), SE->getSCEV(Base));
    if (NoWrap) {
        Offset = addNoWrapFlags(Offset);
        SE->forgetValue(GEP);
    }
    return Offset;
}

const SCEV *SafeAllocs::getSizeOfSCEV(Type *Ty) {
    return SE->getSizeOfExpr(Type::getInt64Ty(Ty->getContext()), Ty);
}

const SCEV *SafeAllocs::getPointerCastOrArithOffset(Instruction *UI, Value *I) {
    switch (UI->getOpcode()) {
        case Instruction::BitCast:
        case Instruction::PtrToInt:
        case Instruction::IntToPtr:
            return SE->getZero(Type::getInt64Ty(UI->getContext()));
        case Instruction::GetElementPtr:
            return getGEPOffsetSCEV(cast<GetElementPtrInst>(UI));
        case Instruction::Add:
            return SE->getSCEV(otherOperand(UI, I));
        case Instruction::Sub:
            if (UI->getOperand(0) == I)
                return SE->getNegativeSCEV(SE->getSCEV(UI->getOperand(1)));
            break;
        default:
            break;
    }
    return nullptr;
}

const SCEV *SafeAllocs::addSCEVs(const SCEV *LHS, const SCEV *RHS) {
    if (!LHS) {
        assert(RHS);
        return RHS;
    }
    if (!RHS) {
        assert(LHS);
        return LHS;
    }
    return SE->getAddExpr(LHS, RHS);
}

/*
static std::string cmpstr(ICmpInst::Predicate Pred, const SCEV *LHS, const SCEV *RHS) {
    std::string s;
    raw_string_ostream os(s);

    LHS->print(os);

    switch (Pred) {
        case CmpInst::ICMP_EQ:  os << " == ";  break;
        case CmpInst::ICMP_NE:  os << " != ";  break;
        case CmpInst::ICMP_UGT: os << " u> ";  break;
        case CmpInst::ICMP_UGE: os << " u>= "; break;
        case CmpInst::ICMP_ULT: os << " u< ";  break;
        case CmpInst::ICMP_ULE: os << " u<= "; break;
        case CmpInst::ICMP_SGT: os << " s> ";  break;
        case CmpInst::ICMP_SGE: os << " s>= "; break;
        case CmpInst::ICMP_SLT: os << " s< ";  break;
        case CmpInst::ICMP_SLE: os << " s<= "; break;
        default:                os << " ??? "; break;
    }

    RHS->print(os);

    os.flush();
    return s;
}
*/

bool SafeAllocs::compareSCEVs(ICmpInst::Predicate Pred, const SCEV *LHS, const SCEV *RHS) {
    //DEBUG_LINE(" compare:    " << cmpstr(Pred, LHS, RHS));
    SE->SimplifyICmpOperands(Pred, LHS, RHS);
    //DEBUG_LINE(" simplified: " << cmpstr(Pred, LHS, RHS));
    bool Result = SE->isKnownPredicate(Pred, LHS, RHS);
    //DEBUG_LINE("     result: " << Result);
    return Result;
}

bool SafeAllocs::compareSCEVs(ICmpInst::Predicate Pred, Value *LHS, Value *RHS) {
    return compareSCEVs(Pred, SE->getSCEV(LHS), SE->getSCEV(RHS));
}

bool SafeAllocs::compareGEPs(ICmpInst::Predicate Pred, GetElementPtrInst *LHS,
        GetElementPtrInst *RHS) {
    Value *BaseL = LHS->getPointerOperand()->stripPointerCasts();
    Value *BaseR = RHS->getPointerOperand()->stripPointerCasts();
    assert(BaseL == BaseR);

    //DEBUG_LINE("   compare GEPs: " << *SE->getSCEV(LHS));
    //DEBUG_LINE("            and: " << *SE->getSCEV(RHS));
    const SCEV *OffsetL = getGEPOffsetSCEV(LHS);
    const SCEV *OffsetR = getGEPOffsetSCEV(RHS);
    //DEBUG_LINE("        OffsetL: " << *OffsetL);
    //DEBUG_LINE("        OffsetR: " << *OffsetR);
    eliminateCommonOperandsForComparison(OffsetL, OffsetR);
    //DEBUG_LINE("          elimL: " << *OffsetL);
    //DEBUG_LINE("          elimR: " << *OffsetR);
    return compareSCEVs(Pred, OffsetL, OffsetR);
}

bool SafeAllocs::eliminateCommonOperandsForComparison(const SCEV *&A, const SCEV *&B) {
    if (A->getSCEVType() != B->getSCEVType())
        return false;

    SCEVTypes Ty = static_cast<SCEVTypes>(A->getSCEVType());

    if (Ty == scAddExpr || Ty == scMulExpr) {
        const SCEVNAryExpr *AN = cast<SCEVNAryExpr>(A);
        const SCEVNAryExpr *BN = cast<SCEVNAryExpr>(B);

        // Only handle binary operators (sufficient for GEPs)
        if (AN->getNumOperands() != 2 || BN->getNumOperands() != 2)
            return false;

        if (AN->getOperand(0) == BN->getOperand(0)) {
            A = AN->getOperand(1);
            B = BN->getOperand(1);
        }
        else if (AN->getOperand(1) == BN->getOperand(1)) {
            A = AN->getOperand(0);
            B = BN->getOperand(0);
        }
        else if (AN->getOperand(0) == BN->getOperand(1)) {
            A = AN->getOperand(1);
            B = BN->getOperand(0);
        }
        else if (AN->getOperand(1) == BN->getOperand(0)) {
            A = AN->getOperand(0);
            B = BN->getOperand(1);
        }
        else {
            return false;
        }

        eliminateCommonOperandsForComparison(A, B);
        return true;
    }
    else if (Ty == scAddRecExpr) {
        const SCEVAddRecExpr *AAR = cast<SCEVAddRecExpr>(A);
        const SCEVAddRecExpr *BAR = cast<SCEVAddRecExpr>(B);

        // Only handle the form A*X+b (again targeting GEPs)
        if (!AAR->isAffine() || !BAR->isAffine())
            return false;

        // FIXME: how do we handle loops?
        //if (AAR->getStart() == BAR->getStart()) {
        //    A = SE->getAddRecExpr();
        //}
    }
    else ifcast(const SCEVCastExpr, AC, A) {
        const SCEVCastExpr *BC = cast<SCEVCastExpr>(B);

        if (AC->getType() != BC->getType())
            return false;

        const SCEV *OpA = AC->getOperand(), *OpB = BC->getOperand();
        if (!eliminateCommonOperandsForComparison(OpA, OpB))
            return false;

        switch (Ty) {
            case scSignExtend:
                A = SE->getSignExtendExpr(OpA, AC->getType());
                B = SE->getSignExtendExpr(OpB, BC->getType());
                break;
            case scZeroExtend:
                A = SE->getZeroExtendExpr(OpA, AC->getType());
                B = SE->getZeroExtendExpr(OpB, BC->getType());
                break;
            case scTruncate:
                A = SE->getTruncateExpr(OpA, AC->getType());
                B = SE->getTruncateExpr(OpB, BC->getType());
                break;
            default:
                break;
        }
    }

    return false;
}
