#include <llvm/Transforms/Utils/Local.h>

#define DEBUG_TYPE "debugnegarith"

#include "utils/Common.h"
#include "utils/CustomFunctionPass.h"

using namespace llvm;

struct DebugNegArith : public CustomFunctionPass {
    static char ID;
    DebugNegArith() : CustomFunctionPass(ID) {}

private:
    const DataLayout *DL;
    Function *CheckFunc;

    bool initializeModule(Module &M) override;
    bool runOnFunction(Function &F) override;

    void instrGep(GetElementPtrInst *Gep);
};

char DebugNegArith::ID = 0;
static RegisterPass<DebugNegArith> X("debug-neg-arith",
        "Insert run-time checks to see if negative arith happens on non-tagged pointers");

STATISTIC(NumGeps,         "Number of GEPs");
STATISTIC(NumConstPosGeps, "Number of dynamically-indexed GEPs");
STATISTIC(NumConstNegGeps, "Number of constant-negative GEPs");
STATISTIC(NumDynGeps,      "Number of constant-positive GEPs");
STATISTIC(NumZeroGeps,     "Number of VTable GEPs");
STATISTIC(NumVtableGeps,   "Number of zero GEPs");

bool DebugNegArith::initializeModule(Module &M) {
    DL = &M.getDataLayout();
    CheckFunc = getNoInstrumentFunction(M, "check_neg_arith");
    return false;
}

void DebugNegArith::instrGep(GetElementPtrInst *Gep) {
    NumGeps++;

    if (Gep->hasAllZeroIndices()) {
        NumZeroGeps++;
        return;
    }

    /* sizetags ignores vtable-related geps already */
    Value *SrcPtr = Gep->getPointerOperand();
    if (SrcPtr->hasName() && SrcPtr->getName().startswith("vtable")) {
        NumVtableGeps++;
        return;
    }
    if (Gep->getNumIndices() == 1) {
        Value *FirstOp = Gep->getOperand(1);
        if (FirstOp->hasName() &&
            FirstOp->getName().startswith("vbase.offset")) {
            NumVtableGeps++;
            return;
        }
    }

    APInt ConstOffset(64, 0);
    if (Gep->accumulateConstantOffset(*DL, ConstOffset)) {
        if (ConstOffset.sgt(0)) {
            NumConstPosGeps++;
            return;
        }
        NumConstNegGeps++;
    } else
        NumDynGeps++;

    IRBuilder<> B(getInsertPointAfter(Gep));
    Value *Offset = EmitGEPOffset(&B, *DL, Gep);
    Value *Ptr = B.CreateBitCast(Gep->getPointerOperand(), CheckFunc->getFunctionType()->getParamType(1));
    B.CreateCall(CheckFunc, { B.getInt64(NumGeps), Ptr, Offset, B.getInt32(Gep->hasAllConstantIndices()) } );
}

bool DebugNegArith::runOnFunction(Function &F) {
    for (inst_iterator II = inst_begin(&F), E = inst_end(&F); II != E; ++II) {
        Instruction *I = &*II;
        ifcast(GetElementPtrInst, Gep, I) {
            instrGep(Gep);
        }
    }

    return true;
}
