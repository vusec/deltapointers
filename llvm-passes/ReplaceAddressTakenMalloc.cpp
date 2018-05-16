#include <llvm/Pass.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Debug.h>
#include <llvm/Support/raw_ostream.h>
#include "llvm/Support/FileSystem.h"

#define DEBUG_TYPE "replace-address-taken-malloc"

#include "builtin/Common.h"
#include "builtin/Allocation.h"

using namespace llvm;

struct ReplaceAddressTakenMalloc : public ModulePass {
    static char ID;
    ReplaceAddressTakenMalloc() : ModulePass(ID) {}
    virtual bool runOnModule(Module &M);
    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
        AU.setPreservesAll();
    }
};

char ReplaceAddressTakenMalloc::ID = 0;
static RegisterPass<ReplaceAddressTakenMalloc> X("replace-address-taken-malloc",
        "Add wrappers around address-taken malloc/free calls to make sure that "
        "all calls to allocation functions are direct");

STATISTIC(NWrappers, "Number of address-taken functions wrapped");
STATISTIC(NUses,     "Number of function pointers replaced");

static Function *makeWrapper(Function *F) {
    Function *Wrapper = Function::Create(F->getFunctionType(),
                                         GlobalValue::InternalLinkage,
                                         Twine("__wrap.") + F->getName(),
                                         F->getParent());
    IRBuilder<> B(BasicBlock::Create(F->getContext(), "entry", Wrapper));

    SmallVector<Value*, 4> Args;
    for (Argument &Arg : Wrapper->args())
        Args.push_back(&Arg);

    if (F->getReturnType()->isVoidTy()) {
        B.CreateCall(F, Args);
        B.CreateRetVoid();
    } else {
        B.CreateRet(B.CreateCall(F, Args, "ret"));
    }

    return Wrapper;
}

bool ReplaceAddressTakenMalloc::runOnModule(Module &M) {
    SmallVector<Function*, 16> WrapFunctions;

    for (Function &F : M) {
        if (F.hasAddressTaken() && (isAllocationFunc(&F) || isFreeFunc(&F)))
            WrapFunctions.push_back(&F);
    }

    for (Function *F : WrapFunctions) {
        DEBUG_LINE("creating wrapper for " << F->getName());
        ++NWrappers;

        Function *Wrapper = makeWrapper(F);
        const User *UU;

        while (F->hasAddressTaken(&UU)) {
            User *U = const_cast<User*>(UU);

            ifcast(ConstantExpr, Expr, U) {
                unsigned i = getOperandNo(Expr, F);
                Constant *Repl = Expr->getWithOperandReplaced(i, Wrapper);
                Expr->replaceAllUsesWith(Repl);
                Expr->destroyConstant();
                NUses += Repl->getNumUses();
            } else {
                U->replaceUsesOfWith(F, Wrapper);
                ++NUses;
            }
        }
    }

    return !WrapFunctions.empty();
}
