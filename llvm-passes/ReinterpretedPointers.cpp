#define DEBUG_TYPE "find-reinterpreted-pointers"

#include "utils/Common.h"
#include "AddressSpace.h"
#include "ReinterpretedPointers.h"

using namespace llvm;

typedef SetVector<Instruction*> PtrIntListT;

char ReinterpretedPointers::ID = 0;
static RegisterPass<ReinterpretedPointers> X("find-reinterpreted-pointers",
        "Find pointers that are cast to integers and identify any uses that "
        "need masking of metadata tags",
        false, true);

void ReinterpretedPointers::getAnalysisUsage(AnalysisUsage &AU) const {
    AU.setPreservesAll();
}

static inline bool isAnd(Instruction *I) {
    return I->isBinaryOp() && I->getOpcode() == Instruction::And;
}

/*
 * A pointer mask preserves the high bits if if the mask is constant and has
 * all ones in the upper (metadata) bits.
 */
static bool andDefinitelyPreservesHighBits(Instruction *I, Instruction *PtrOp) {
    unsigned OtherOpIndex = I->getOperand(0) == PtrOp ? 1 : 0;
    ifcast(ConstantInt, Mask, I->getOperand(OtherOpIndex))
        return Mask->getZExtValue() >= ~getAddressSpaceMask();
    return false;
}

/*
 * A pointer mask zeroes the high bits if if the mask is constant and has all
 * zeroes in the upper (metadata) bits.
 */
static bool andDefinitelyZeroesHighBits(Instruction *I, Instruction *PtrOp) {
    unsigned OtherOpIndex = I->getOperand(0) == PtrOp ? 1 : 0;
    ifcast(ConstantInt, Mask, I->getOperand(OtherOpIndex))
        return Mask->getZExtValue() <= getAddressSpaceMask();
    return false;
}

/*
 * Check if an instruction needs to mask metadata bits of a ptrint.
 */
static bool breaksWithPointerTag(Instruction *I, Instruction *PtrInt) {
    /* Trivial:
     * - cmp, sub, add, xor, rem, div, gep, sh[rl], switch, ret, itofp, insert
     *   (xors are sometimes used to create uglygeps)
     * - external/asm/intrinsic call */
    switch (I->getOpcode()) {
        case Instruction::ICmp:
        case Instruction::Sub:
        case Instruction::Add:
        case Instruction::Xor:
        case Instruction::URem:
        case Instruction::SRem:          // gcc
        case Instruction::Mul:           // perlbench, h264ref
        case Instruction::SDiv:          // omnetpp
        case Instruction::UDiv:
        case Instruction::GetElementPtr:
        case Instruction::LShr:
        case Instruction::AShr:
        case Instruction::Shl:
        case Instruction::Or:            // xalancbmk (TraverseSchema.cpp:2658)
        case Instruction::Switch:
        case Instruction::SIToFP:        // omnetpp
        case Instruction::UIToFP:        // perl FIXME: wtf... should we mask this?
        case Instruction::InsertElement: // dealII
        case Instruction::InsertValue:   // xalancbmk
            return true;
    }

    ifcast(CallInst, CI, I) {
        Function *F = CI->getCalledFunction();
        return !F || F->isIntrinsic() || F->isDeclaration();
    }

    ifcast(InvokeInst, IV, I) {
        Function *F = IV->getCalledFunction();
        return !F || F->isDeclaration();
    }

    /* Non-trivial, these need more analysis:
     * - and: if the mask may not preserve metadata bits */
    if (isAnd(I))
        return !andDefinitelyPreservesHighBits(I, PtrInt);

    return false;
}

/*
 * Identify uses of ptrints that definitely do not need masking:
 * - store, inttoptr, bitcast (int -> ptr)
 * - internal call: don't know if causes problems, just print a warning for now
 * - and: if the mask already zeroes the metapointer
 * - trunc: if the destination type fits within the address space bits
 */
static bool doesNotBreakWithPointerTag(Instruction *I, Instruction *PtrInt) {
    if (isa<StoreInst>(I) || isa<IntToPtrInst>(I))
        return true;

    ifcast(BitCastInst, BC, I) {
        assert(isPtrIntTy(BC->getSrcTy()));

        if (!BC->getDestTy()->isPointerTy()) {
            DEBUG_LINE("Warning: bitcast user of ptrint might need masking:");
            DEBUG_LINE("  ptrint: " << *PtrInt);
            DEBUG_LINE("  bitcast:" << *BC);
            return true;
        }

        return BC->getDestTy()->isPointerTy();
    }

    ifcast(CallInst, CI, I) {
        Function *F = CI->getCalledFunction();
        if (!F || F->isIntrinsic() || F->isDeclaration())
            return false;

        //DEBUG_LINE("Warning: call to internal function might need to mask ptrint:");
        //DEBUG_LINE("  ptrint:" << *PtrInt);
        //DEBUG_LINE("  call:  " << *CI);
        return true;
    }

    ifcast(InvokeInst, IV, I) {
        Function *F = IV->getCalledFunction();
        if (!F || F->isDeclaration())
            return false;

        //DEBUG_LINE("Warning: invoke of internal method might need to mask ptrint:");
        //DEBUG_LINE("  ptrint:" << *PtrInt);
        //DEBUG_LINE("  call:  " << *IV);
        return true;
    }

    if (isAnd(I))
        return andDefinitelyZeroesHighBits(I, PtrInt);

    ifcast(TruncInst, TI, I) {
        IntegerType *DestTy = cast<IntegerType>(TI->getDestTy());
        return DestTy->getBitWidth() <= AddressSpaceBits;
    }

    if (isa<ReturnInst>(I))
        return true;

    return false;
}

static bool propagatesPointerTag(Instruction *I, Instruction *Ptr) {
    if (isa<PHINode>(I) || isa<SelectInst>(I))
        return true;

    if (isAnd(I))
        return andDefinitelyPreservesHighBits(I, Ptr);

    return false;
}

/*
 * Collect users for a ptrint source that need masking of metadata bits.
 * Recursively follow phi nodes, selects and metadata-preserving pointer masks.
 * We whitelist all uses that definitely need or don't need masking and error
 * if we encounter something unexpected.
 */
static void findNullTagUsers(Instruction *I, SmallVectorImpl<Instruction*> &NullTagUsers) {
    for (User *U : I->users()) {
        ifncast(Instruction, UI, U) {
            continue;
        }
        else if (propagatesPointerTag(UI, I) || doesNotBreakWithPointerTag(UI, I)) {
            continue;
        }
        else if (breaksWithPointerTag(UI, I)) {
            NullTagUsers.push_back(UI);
        }
        else {
            errs() << "Error: found use of ptrint in ";
            errs() << I->getParent()->getParent()->getName();
            errs() << " and not sure if should mask.\n";
            errs() << "  ptrint:" << *I << "\n";
            errs() << "  user:  " << *UI << "\n";
            exit(1);
        }
    }
}

static bool isPointerPointerBitCast(Value *V) {
    std::vector<Value*> Origins;

    ifcast(PHINode, PN, V)
        collectPHIOrigins(PN, Origins);
    else
        Origins.push_back(V);

    for (Value *Origin : Origins) {
        ifcast(BitCastOperator, BC, Origin) {
            assert(isPtrIntTy(cast<PointerType>(BC->getDestTy())->getElementType()));
            PointerType *SrcTy = dyn_cast<PointerType>(BC->getSrcTy());
            assert(SrcTy);
            if (SrcTy->getElementType()->isPointerTy())
                return true;
        }
    }

    return false;
}

static bool isUsedAsPointer(Instruction *I, PtrIntListT &PtrInts) {
    for (User *U : I->users()) {
        Instruction *UI = dyn_cast<Instruction>(U);
        if (!UI)
            continue;

        if (isa<IntToPtrInst>(UI)) {
            return true;
        } else ifcast(StoreInst, SI, UI) {
            return isPointerPointerBitCast(SI->getPointerOperand());
        } else if (isa<PHINode>(UI)) {
            return PtrInts.count(UI) > 0;
        } else if (UI->isBinaryOp() && UI->getOpcode() == Instruction::Sub) {
            Instruction *Other = dyn_cast<Instruction>(otherOperand(UI, I));
            return PtrInts.count(UI) > 0 ||
                (Other && PtrInts.count(Other) > 0) ||
                UI->getName().startswith("sub.ptr.sub");
        }
    }

    return false;
}

void ReinterpretedPointers::addNullTagUser(Instruction *PtrInt, Instruction *User) {
    assert(isPtrIntTy(PtrInt->getType()));

    auto it = NullTagUsers.find(PtrInt);

    if (it == NullTagUsers.end()) {
        UserListT NullTagUserList;
        NullTagUserList.push_back(User);
        NullTagUsers[PtrInt] = NullTagUserList;
        //NullTagUsers[PtrInt] = std::move(NullTagUserList);
    } else {
        for (Instruction *Existing : it->second) {
            if (Existing == User)
                return;
        }
        it->second.push_back(User);
    }
}

#if 0
static LoadInst *getLoadInst(Value *V, std::set<PHINode*> &VisitedPHINodes) {
    ifcast(LoadInst, LI, V)
        return LI;

    ifcast(PHINode, PN, V) {
        if (VisitedPHINodes.count(PN) == 0) {
            VisitedPHINodes.insert(PN);
            for (Use &U : PN->operands()) {
                if (LoadInst *LI = getLoadInst(U.get(), VisitedPHINodes))
                    return LI;
            }
        }
    }

    return nullptr;
}

static StructType *innerStruct(StructType *Ty) {
    if (!Ty->isOpaque()) {
        Type *ElTy = Ty->getElementType(0);
        while (ElTy->isStructTy()) {
            Ty = cast<StructType>(ElTy);
            if (Ty->isOpaque())
                break;
            ElTy = Ty->getElementType(0);
        }
    }
    return Ty;
}

/*
 * Perlbench hotfix:
 *
 * op.c line 2753 has the following function:
 * Perl_pmruntime(pTHX_ OP *o, OP *expr, OP *repl)
 * {
 *     PMOP *pm;              // alternative fix: make this definition volatile
 *     ...
 *     pm = (PMOP*)o;         // assigned only once so copy propagation happens
 *     ...
 *     pm->op_pmflags |= ...; // replaced with bitcast(gep(o, 2, 1) -> i64*)
 *     ...
 * }
 *
 * &pm->op_pmflags is replaced with a bitcast to i64* after copy propagation.
 * The problem is that because o has a pointer at index 1, our analysis thinks
 * the loaded value is a pointer and masks out the upper bits. These bits
 * contain a flag that is zeroed, causing control flow to differ, slightly
 * changing the output of perlbench. We whitelist the getelementptr here to be
 * able to include perlbench in our benchmarks.
 */
static bool isWhitelisted(LoadInst *LI) {
    if (LI->getParent()->getParent()->getName() != "Perl_pmruntime")
        return false;

    ifcast(BitCastInst, BC, LI->getPointerOperand()) {
        ifcast(PointerType, PtrTy, BC->getSrcTy()) {
            ifcast(PointerType, NestedPtrTy, PtrTy->getElementType()) {
                ifcast(StructType, StructTy, NestedPtrTy->getElementType()) {
                    if (StructTy->getName() != "struct.op")
                        return false;

                    ifcast(GetElementPtrInst, Gep, BC->getOperand(0)) {
                        if (Gep->hasName() && Gep->getName().startswith("op_pmflags")) {
                            dbgs() << "Warning: encountered whitelisted pm->op_pmflags:\n";
                            dbgs() << *Gep << "\n";
                            dbgs() << *BC << "\n";
                            return true;
                        }
                    }
                }
            }
        }
    }

    return false;
}

/*
 * A load instruction might load a pointer from memory as an integer. This can
 * go through one or more indirections (other loads) but it should end up at a
 * bitcast of a pointer to an int pointer (e.g., x** -> i64*). We try to
 * determine the number of indirections by adding the number of loads to the
 * number of indirections in the type, also tracking iopnters in composite
 * types. When the source type is a struct that begins with a pointer, we
 * heuristically check if the pointer is an i8* and if so, assume the struct is
 * actually a union type created by LLVM. We also track load insts through phi
 * nodes, in that case just use the first operand that is a load instruction.
 */
static Possibility loadsPointerAsInt(LoadInst *LI) {
    if (!isPtrIntTy(LI->getType()))
        return No;

    if (isWhitelisted(LI))
        return No;

    int LoadCount = 0;
    Value *Src;
    std::set<PHINode*> VisitedPHINodes;
    LoadInst *NestedLI = LI;
    do {
        Src = NestedLI->getPointerOperand();
        LoadCount++;
        VisitedPHINodes.clear();
    } while ((NestedLI = getLoadInst(Src, VisitedPHINodes)));

    ifcast(BitCastOperator, BC, Src) {
        Type *SrcTy = BC->getSrcTy();
        assert(SrcTy->isPointerTy());
        PointerType *PtrTy = cast<PointerType>(SrcTy);
        int PointerLevel = 0;
        std::set<StructType*> encounteredStructs;
        bool FromStruct = false;
        bool FromUnion = false;

        while (PtrTy) {
            SrcTy = PtrTy->getElementType();
            PointerLevel++;
            ifcast(StructType, StructTy, SrcTy) {
                if (StructTy->getNumElements() == 0) {
                    DEBUG_LINE("Warning: (WTF) struct element is empty in type " << *BC->getSrcTy());
                    DEBUG_LINE("  bitcast:" << *BC);
                    DEBUG_LINE("  load:   " << *LI);
                    return Maybe;  // FIXME: should we return Yes here? (find out if this is indeed a vtable)
                }
                StructTy = innerStruct(StructTy);
                FromUnion = false;

                if (!StructTy->isOpaque() && encounteredStructs.count(StructTy) == 0) {
                    encounteredStructs.insert(StructTy);
                    SrcTy = StructTy->getElementType(0);
                    FromStruct = true;

                    if (SrcTy->isPointerTy() && isUnionType(StructTy))
                        FromUnion = true;
                }
            }
            while (SrcTy->isArrayTy() || SrcTy->isVectorTy()) {
                SrcTy = SrcTy->getSequentialElementType();
            }
            PtrTy = dyn_cast<PointerType>(SrcTy);
        }

        if (PointerLevel > LoadCount) {
            // x** -> i64*

            ifcast(GEPOperator, Gep, BC->getOperand(0)) {
                // The pointer may originate from a getelementptr of a struct
                // in a union. The union-indexed pointer may actually be an int
                // in an other struct in the union. Since LLVM flattens unions
                // to the biggest type, we cannot check this.
                if (isUnionType(Gep->getSourceElementType())) {
                    //DEBUG_LINE("Warning: union-indexed type may not be a pointer:");
                    //DEBUG_LINE(*Gep);
                    return Maybe;
                }

                // FIXME For now, just ignore anythins that comes from a
                // gep->bitcast to avoid being over-conservative
                if (Gep->getSourceElementType()->isStructTy()) {
                    //DEBUG_LINE("Warning: ignoring struct-indexed type:");
                    //DEBUG_LINE(*Gep);
                    return Maybe;
                }
            }

            return (PointerLevel == LoadCount + 1 && FromUnion) ? Maybe : Yes;
        }
        else if (PointerLevel == LoadCount) {
            assert(!SrcTy->isArrayTy());
            assert(!SrcTy->isVectorTy());
            if (SrcTy->isStructTy()) {
                return Maybe;
            } else if (SrcTy->isIntegerTy(8) && FromStruct) {
                // struct { i8* }
                return Maybe;
            } else if (SrcTy->isIntegerTy() || SrcTy->isFloatingPointTy()) {
                return No;
            } else {
                Function *F = LI->getParent()->getParent();
                assert(F);
                errs() << "type:  " << *SrcTy << "in " << F->getName() << "\n";
                errs() << "load:"  << *LI << "\n";
                assert(false);
                return Maybe;
            }
        }
        else /* if (PointerLevel < LoadCount) */ {
            assert(!SrcTy->isArrayTy());
            assert(!SrcTy->isVectorTy());
            return Maybe;
        }
    }

    return No;
}
#endif

/*
 * Use Type Based Alias Analysis results to see if a load inst loads a pointer
 * as an integer.
 * See also: http://releases.llvm.org/3.8.0/docs/LangRef.html#tbaa-metadata
 */
static Possibility loadsPointerAsInt(LoadInst *LI) {
    if (MDNode *TBAA = LI->getMetadata("tbaa")) {
        MDNode *TypeOp = cast<MDNode>(TBAA->getOperand(1));
        MDString *TypeName = cast<MDString>(TypeOp->getOperand(0));
        if (TypeName->getString() == "any pointer")
            return Yes;
    } else {
        // Find load [-> load] -> bitcast chain, return No if no chain found
        while (LoadInst *NestedLI = dyn_cast<LoadInst>(LI->getPointerOperand()))
            LI = NestedLI;

        if (isa<BitCastOperator>(LI->getPointerOperand()))
            return Maybe;

        if (isa<IntToPtrInst>(LI->getPointerOperand()))
            return Maybe;
    }

    return No;
}

static bool isPtrVecTy(Type *Ty) {
    VectorType *VecTy = dyn_cast<VectorType>(Ty);
    return VecTy && isPtrIntTy(VecTy->getElementType());
}

bool ReinterpretedPointers::runOnFunction(Function &F) {
    PtrIntListT PtrInts, PtrVecs;
    SmallSetVector<Instruction*, 10> IntLoads;

    // First find trivial cases in a first pass
    foreach_func_inst(&F, I) {
        if (isPtrIntTy(I->getType())) {
            if (isa<PtrToIntInst>(I)) {
                PtrInts.insert(I);
            }
            else ifcast(BitCastInst, BC, I) {
                if (BC->getSrcTy()->isPointerTy())
                    PtrInts.insert(I);
            }
            else ifcast(LoadInst, LI, I) {
                switch (loadsPointerAsInt(LI)) {
                    case Yes:   PtrInts.insert(I); break;
                    case Maybe: IntLoads.insert(I); break;
                    case No:    break;
                }
            }
        }
        else ifcast(LoadInst, LI, I) {
            if (isPtrVecTy(I->getType()) && loadsPointerAsInt(LI) == Yes)
                PtrVecs.insert(I);
        }
    }

    // Look at users of uncertain ptrints (loads) to see if they are used as a
    // pointer. Reiterate until no more pointers are found (since
    // isUsedAsPointer uses the tagged ptrints). Propagate ptrint tags to phi
    // nodes, selects and pointer masks.
    size_t OldSize;
    do {
        OldSize = PtrInts.size() + PtrVecs.size();

        foreach_func_inst(&F, I) {
            Type *Ty = I->getType();

            if (isPtrIntTy(Ty)) {
                if (PtrInts.count(I) > 0) {
                    foreach(Instruction, UI, I->users()) {
                        if (isa<PHINode>(UI) || isa<SelectInst>(UI)) {
                            PtrInts.insert(UI);
                        }
                        else if (isAnd(UI) && andDefinitelyPreservesHighBits(UI, I)) {
                            PtrInts.insert(UI);
                        }
                    }
                }
                else if (isa<LoadInst>(I) && IntLoads.count(I) > 0 &&
                         isUsedAsPointer(I, PtrInts)) {
                    PtrInts.insert(I);
                    IntLoads.remove(I);
                }
            }
            else if (PtrVecs.count(I) > 0) {
                foreach(Instruction, UI, I->users()) {
                    if (isa<PHINode>(UI) ||
                        isa<InsertElementInst>(UI) ||
                        isa<ShuffleVectorInst>(UI) ||
                        isa<SelectInst>(UI) ||
                        UI->isBinaryOp()) {
                        PtrVecs.insert(UI);
                    }
                    else if (isa<ExtractElementInst>(UI)) {
                        PtrInts.insert(UI);
                    }
                    else ifcast(BitCastInst, BC, UI) {
                        if (!BC->getDestTy()->isIntegerTy(128)) {
                            errs() << "Warning: unexpected bitcast of ptrvec in " << F.getName() << ":\n";
                            errs() << "  ptrvec: " << *I << "\n";
                            errs() << "  bitcast:" << *BC << "\n";
                        }
                        if (BC->getDestTy()->isIntegerTy())
                            PtrVecs.insert(UI);
                    }
                    else if (isa<TruncInst>(UI)) {
                        if (isPtrIntTy(UI->getType())) {
                            PtrInts.insert(UI);
                        } else {
                            assert(isa<VectorType>(UI->getType()));
                            PtrVecs.insert(UI);
                        }
                    }
                    else if (!isa<StoreInst>(UI) &&
                             !isa<ICmpInst>(UI)) {
                        errs() << "unexpected use of ptrvec in " << F.getName() << ":\n";
                        errs() << "  ptrvec:" << *I << "\n";
                        errs() << "  user:  " << *UI << "\n";
                        exit(1);
                    }
                }
            }
        }
    } while (PtrInts.size() + PtrVecs.size() != OldSize);

    // Tag users for all ptrints that need masking
    SmallVector<Instruction *, 4> PtrIntNullTagUsers;

    for (Instruction *PtrInt : PtrInts) {
        PtrIntNullTagUsers.clear();
        findNullTagUsers(PtrInt, PtrIntNullTagUsers);

        for (Instruction *User : PtrIntNullTagUsers)
            addNullTagUser(PtrInt, User);
    }

    // Emit warnings for loads that could not be determined to be pointers
    for (Instruction *LI : IntLoads) {
        PtrIntNullTagUsers.clear();
        findNullTagUsers(LI, PtrIntNullTagUsers);

        if (!PtrIntNullTagUsers.empty()) {
            DEBUG_LINE("Warning: possible pointer load in " << F.getName() <<
                       " has users that would need masking");
            DEBUG_LINE("  load:" << *LI);
            for (Instruction *User : PtrIntNullTagUsers)
                DEBUG_LINE("  user:" << *User);
        }
    }

    return false;
}
