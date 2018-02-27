#include "utils/Common.h"
#include "GlobalOpt.h"

using namespace llvm;

/*
 * Copied from llvm/lib/Transforms/IPO/GlobalOpt.cpp
 */

/// C may have non-instruction users. Can all of those users be turned into
/// instructions?
bool allNonInstructionUsersCanBeMadeInstructions(Constant *C) {
  // We don't do this exhaustively. The most common pattern that we really need
  // to care about is a constant GEP or constant bitcast - so just looking
  // through one single ConstantExpr.
  //
  // The set of constants that this function returns true for must be able to be
  // handled by makeAllConstantUsesInstructions.
  for (auto *U : C->users()) {
    if (isa<PHINode>(U))
      // A phi node using a global as a const, cannot be replaced trivially
      // because the insert point needs to be the corresponding predecessor
      return false;
    if (isa<Instruction>(U))
      continue;
    if (!isa<ConstantExpr>(U))
      // Non instruction, non-constantexpr user; cannot convert this.
      return false;
    for (auto *UU : U->users()) {
      if (!isa<Instruction>(UU))
        // A constantexpr used by another constant. We don't try and recurse any
        // further but just bail out at this point.
        return false;
      if (isa<PHINode>(UU))
        // because the insert point needs to be the corresponding predecessor
        return false;
    }
  }

  return true;
}

/// C may have non-instruction users, and
/// allNonInstructionUsersCanBeMadeInstructions has returned true. Convert the
/// non-instruction users to instructions.
void makeAllConstantUsesInstructions(Constant *C) {
  SmallVector<ConstantExpr*,4> Users;
  for (auto *U : C->users()) {
    if (isa<ConstantExpr>(U))
      Users.push_back(cast<ConstantExpr>(U));
    else
      // We should never get here; allNonInstructionUsersCanBeMadeInstructions
      // should not have returned true for C.
      assert(
          isa<Instruction>(U) &&
          "Can't transform non-constantexpr non-instruction to instruction!");
  }

  SmallVector<Value*,4> UUsers;
  for (auto *U : Users) {
    UUsers.clear();
    for (auto *UU : U->users())
      UUsers.push_back(UU);
    for (auto *UU : UUsers) {
      Instruction *UI = cast<Instruction>(UU);
      Instruction *NewU = U->getAsInstruction();
      NewU->insertBefore(UI);
      UI->replaceUsesOfWith(U, NewU);
    }
    U->dropAllReferences();
  }
}
