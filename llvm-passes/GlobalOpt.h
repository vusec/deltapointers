#ifndef GLOBAL_OPT_UTILS_H
#define GLOBAL_OPT_UTILS_H

#include <llvm/IR/Constant.h>

bool allNonInstructionUsersCanBeMadeInstructions(llvm::Constant *C);
void makeAllConstantUsesInstructions(llvm::Constant *C);

#endif /* !GLOBAL_OPT_UTILS_H */
