#ifndef SAFE_ALLOCS_H
#define SAFE_ALLOCS_H

#include <llvm/Pass.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Dominators.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/Transforms/Utils/LoopUtils.h>

#include "utils/Allocation.h"

using namespace llvm;

class SafeAllocsBase {
public:
    virtual ~SafeAllocsBase() {}

    virtual bool needsTag(Value *Allocation) = 0;
    virtual bool needsMask(Instruction *I, Value *Operand) = 0;
    virtual bool needsPropagation(GetElementPtrInst *GEP) = 0;
    virtual GetElementPtrInst *getPreemptedOffset(GetElementPtrInst *GEP) = 0;

    // Aliases for readability
    inline bool hasTag(Value *Ptr) { return needsTag(Ptr); }
    inline bool needsPropagation(Instruction *I) {
        assert(isa<CallInst>(I) || isa<InvokeInst>(I));
        return hasTag(I);
    }
};

class SafeAllocs : public ModulePass, public SafeAllocsBase {
public:
    static char ID;
    SafeAllocs() : ModulePass(ID) {}

    bool runOnModule(Module &M) override;
    void getAnalysisUsage(AnalysisUsage &AU) const override;

    bool needsTag(Value *Allocation) override;
    bool needsMask(Instruction *I, Value *Operand) override;
    bool needsPropagation(GetElementPtrInst *GEP) override;
    GetElementPtrInst *getPreemptedOffset(GetElementPtrInst *GEP) override;

private:
    const DataLayout *DL;
    DominatorTree *DT;
    LoopInfo *LI;
    ScalarEvolution *SE;

    DenseSet<Value*> SafeAllocations;
    DenseSet<GetElementPtrInst*> SafeGEPs;
    DenseSet<std::pair<Instruction*, Value*>> SafeMaskSites;
    DenseMap<GetElementPtrInst*, GetElementPtrInst*> PreemptedArithOffsets;

    void setNoTag(Value *Allocation);
    void setNoMask(Instruction *I, Value *Operand);
    void setNoPropagation(GetElementPtrInst *GEP);
    void setPreemptedOffset(GetElementPtrInst *CheckGEP,
            GetElementPtrInst *OffsetGEP);

    void propagateAllocationBounds(Function &F,
            DenseMap<Value*, const SCEV*> &PointerBounds);
    void findSafeGEPs(Function &F,
            DenseMap<Value*, const SCEV*> &PointerBounds);
    void findSafeAllocations(Function &F);
    void preemptBoundChecks(Function &F);
    void findSafeGlobals(Module &M);
    void propagateSafeTags();

    bool isNotDereferencedBeyondNBytes(Value *Ptr,
            const SCEV *DistanceToEndOfObject);
    bool findAllDereferencedBytes(Value *Ptr,
            SmallVectorImpl<const SCEV*> &DerefBytes);

    bool isNotDereferencedInLastLoopIteration(
        GetElementPtrInst *GEP, InductionDescriptor &D);
    const SCEV *addNoWrapFlags(const SCEV *V);
    const SCEV *getGEPOffsetSCEV(GetElementPtrInst *GEP, bool NoWrap=false);
    const SCEV *getSizeOfSCEV(Type *Ty);
    const SCEV *getPointerCastOrArithOffset(Instruction *UI, Value *I);
    const SCEV *addSCEVs(const SCEV *LHS, const SCEV *RHS);
    bool compareSCEVs(ICmpInst::Predicate Pred, const SCEV *LHS, const SCEV *RHS);
    bool compareSCEVs(ICmpInst::Predicate Pred, Value *LHS, Value *RHS);
    bool compareGEPs(ICmpInst::Predicate Pred, GetElementPtrInst *LHS, GetElementPtrInst *RHS);
    bool eliminateCommonOperandsForComparison(const SCEV *&A, const SCEV *&B);
};

#endif /* !SAFE_ALLOCS_H */
