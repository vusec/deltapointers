#ifndef TAG_GLOBALS_CONST_H
#define TAG_GLOBALS_CONST_H

#include <llvm/IR/Module.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Constant.h>

bool canTagGlobal(llvm::GlobalVariable &GV);

void tagGlobal(llvm::GlobalVariable &GV, uint64_t Tag);

void tagGlobal(llvm::GlobalVariable &GV, llvm::Constant *Tag);

#endif /* !TAG_GLOBALS_CONST_H */
