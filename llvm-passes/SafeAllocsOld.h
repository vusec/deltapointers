#ifndef SAFE_ALLOCS_OLD_H
#define SAFE_ALLOCS_OLD_H

#include <llvm/Pass.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallSet.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/Analysis/ScalarEvolutionExpander.h>

#include "utils/Allocation.h"
#include "SafeAllocs.h"

using namespace llvm;

class SafeAllocsOld : public ModulePass, public SafeAllocsBase {
public:
    static char ID;
    SafeAllocsOld() : ModulePass(ID) {}

    bool runOnModule(Module &M) override;
    void getAnalysisUsage(AnalysisUsage &AU) const override;

    // New API
    virtual bool needsTag(Value *Allocation) {
        return !isSafe(Allocation);
    }
    virtual bool needsMask(Instruction *I __attribute__((unused)), Value *Operand) {
        return !isSafe(Operand);
    }
    virtual bool needsPropagation(GetElementPtrInst *GEP) {
        return !isSafe(GEP);
    }
    virtual GetElementPtrInst *getPreemptedOffset(GetElementPtrInst *GEP) {
        return PreemptedArithOffsets.lookup(GEP);
    }

private:
    struct BoundT;
    typedef DenseMap<Value*, BoundT> BoundsT;

    const DataLayout *DL;
    TargetLibraryInfo *TLI;
    LoopInfo *LI;
    ScalarEvolution *SE;
    DenseSet<Value*> SafePointers;
    SmallSet<std::pair<User*, Value*>, 16> Visited;
    DenseSet<Instruction*> UnsafeDerefs;
    DenseMap<GetElementPtrInst*, GetElementPtrInst*> PreemptedArithOffsets;

    // Old API
    bool isSafe(Value *Ptr);
    //bool hasPreemptedOffset(GetElementPtrInst *GEP, int64_t &Offset);

    bool isSafePtr(Value *ptr, uint64_t size);
    bool isUnsafeDeref(Instruction *I, BoundsT &PtrBounds, unsigned Depth);
    bool isPtrUseSafe(Instruction *U, Value *Ptr, BoundsT &PtrBounds, unsigned Depth);
    bool areAllPtrUsesSafe(Value *Ptr, BoundsT &PtrBounds, unsigned Depth);
    void setSafe(Instruction *I, Value *Ptr);
    bool hasHoistableIndices(GetElementPtrInst *GEP);
    void markIntermediateExpandedInstsAsSafe(SCEVExpander &Expander, Value *Expanded);
    void hoistConstGEPOffsetsFromLoops(Function &F, bool &Changed);
    bool hoistBoundCheckFromLoop(GetElementPtrInst *GEP);
    void checkArgument(Argument *Arg, bool &Changed);
    void checkAllocation(AllocationSite &AS, bool &Changed);
    void checkGlobals(Module &M);
    void preemptBoundChecks(BasicBlock &BB, bool &Changed);
    Value *maskPointer(Value *Ptr, IRBuilder<> &B, bool MayPreserveOverflowBit);
};

#endif /* !SAFE_ALLOCS_OLD_H */
