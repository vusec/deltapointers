#include <llvm/Transforms/Utils/Local.h>

#define DEBUG_TYPE "runtime-stats"

#include "builtin/Common.h"
#include "builtin/CustomFunctionPass.h"

using namespace llvm;

struct RuntimeStats : public CustomFunctionPass {
    static char ID;
    RuntimeStats() : CustomFunctionPass(ID) {}

private:
    const DataLayout *DL;

    Function *RTSGEPFunc;
    Function *RTSLoadFunc;
    Function *RTSStoreFunc;
    Type *RTSPtrTy;

    bool initializeModule(Module &M) override;
    bool runOnFunction(Function &F) override;
};

char RuntimeStats::ID = 0;
static RegisterPass<RuntimeStats> X("runtime-stats",
        "Instrument calls to run-time statistics counters");

bool RuntimeStats::initializeModule(Module &M) {
    DL = &M.getDataLayout();
    RTSGEPFunc = getNoInstrumentFunction(M, "rts_gep");
    RTSLoadFunc = getNoInstrumentFunction(M, "rts_load");
    RTSStoreFunc = getNoInstrumentFunction(M, "rts_store");
    RTSPtrTy = RTSLoadFunc->getFunctionType()->getParamType(0);
    return false;
}


bool RuntimeStats::runOnFunction(Function &F) {
    for (inst_iterator II = inst_begin(&F), E = inst_end(&F); II != E; ++II) {
        Instruction *I = &*II;

        IRBuilder<> B(I);
        ifcast(LoadInst, LI, I) {
            Value *Ptr = B.CreateBitCast(LI->getPointerOperand(), RTSPtrTy);
            B.CreateCall(RTSLoadFunc, { Ptr });
        } else ifcast(StoreInst, SI, I) {
            Value *Ptr = B.CreateBitCast(SI->getPointerOperand(), RTSPtrTy);
            B.CreateCall(RTSStoreFunc, { Ptr });
        } else ifcast(GetElementPtrInst, GEP, I) {
            Value *Offset = EmitGEPOffset(&B, *DL, GEP);
            Value *Ptr = B.CreateBitCast(GEP->getPointerOperand(), RTSPtrTy);
            B.CreateCall(RTSGEPFunc, { Ptr, Offset, B.getInt32(GEP->hasAllConstantIndices()) });
        }
    }

    return true;
}
