#ifndef _REINTERPRETED_POINTERS_H
#define _REINTERPRETED_POINTERS_H

#include <llvm/Pass.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Instruction.h>
#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/TinyPtrVector.h>

#include "utils/CustomFunctionPass.h"

using namespace llvm;

struct ReinterpretedPointers : public CustomFunctionPass {
    typedef TinyPtrVector<Instruction*> UserListT;

    static char ID;
    ReinterpretedPointers() : CustomFunctionPass(ID) {};

    bool hasNullTagUsers(Instruction *I) {
        return NullTagUsers.count(I) > 0;
    }

    const UserListT &getNullTagUsers(Instruction *I) {
        return NullTagUsers[I];
    }

private:
    DenseMap<Instruction*, UserListT> NullTagUsers;

    bool runOnFunction(Function &F) override;
    void getAnalysisUsage(AnalysisUsage &AU) const override;
    void addNullTagUser(Instruction *PtrInt, Instruction *User);
};

#endif /* _REINTERPRETED_POINTERS_H */
