/*
 * Check if all dereferenced pointers are within the address space limits
 * enforced by shrinkaddrspace (this pass basically tests if shrinkaddrspace
 * works correctly).
 *
 * We could aso check the addresses of globals here, but those are just
 * wherever you put the data sections so you can also check that with readelf.
 */

#define DEBUG_TYPE "check-address-space"

#include "builtin/Common.h"
#include "builtin/CustomFunctionPass.h"
#include "AddressSpace.h"
#include "SafeAllocs.h"
#include "SafeAllocsOld.h"
#include "ReinterpretedPointers.h"

using namespace llvm;

class CheckAddrSpace : public CustomFunctionPass {
public:
    static char ID;
    CheckAddrSpace() : CustomFunctionPass(ID) {}

    virtual void getAnalysisUsage(AnalysisUsage &AU) const;

private:
    Module *M;
    Function *CheckFunc;

    bool runOnFunction(Function &F) override;
    bool initializeModule(Module &M) override;

    void instrumentCallAlloc(CallSite *CS);
    void instrumentCallExt(CallSite *CS);
    void instrumentCallExtWrap(CallSite *CS);
    void instrumentCallByval(CallSite *CS);
    void instrumentCallExtNestedPtrs(CallSite *CS);
    void instrumentCmpPtr(CmpInst *ins);
    void instrumentPtrInt(Instruction *ins);
    void instrumentMemAccess(Instruction *ins);
    void instrumentGlobals(Module &M);

    void checkPointer(Value *V, IRBuilder<> &B);
    void checkPointerArgs(CallSite *CS);
    void checkNestedPointers(Value *val, CompositeType *elTy,
            std::vector<Value*> &indices, IRBuilder<> &B);
};

void CheckAddrSpace::getAnalysisUsage(AnalysisUsage &AU) const {
    AU.addPreserved<SafeAllocs>();
    AU.addPreserved<SafeAllocsOld>();
    AU.addPreserved<ReinterpretedPointers>();
    AU.addUsedIfAvailable<ReinterpretedPointers>();
}

char CheckAddrSpace::ID = 0;
static RegisterPass<CheckAddrSpace> X("check-address-space",
        "Check pointers for nonzero upper bits (to test addrspace shrinking)");

STATISTIC(NChecks, "Number of pointer checks inserted");

void CheckAddrSpace::checkPointer(Value *V, IRBuilder<> &B) {
    assert(CheckFunc);
    if (V->getType()->isPointerTy())
        V = B.CreatePtrToInt(V, B.getInt64Ty(), Twine(V->getName()) + "_as_int");
    assert(isPtrIntTy(V->getType()));
    B.CreateCall(CheckFunc, {V, B.getInt64(++NChecks)});
}

void CheckAddrSpace::checkPointerArgs(CallSite *CS) {
    IRBuilder<> B(CS->getInstruction());

    for (unsigned i = 0, n = CS->getNumArgOperands(); i < n; i++) {
        Value *arg = CS->getArgOperand(i);
        if (arg->getType()->isPointerTy())
            checkPointer(arg, B);
    }
}

/*
 * Mask pointers to external functions.
 */
void CheckAddrSpace::instrumentCallExt(CallSite *CS) {
    Function *F = CS->getCalledFunction();

    /* XXX inline asm should actually be masked, but currently our tests rely on
     * these semantics. For for instance nginx breaks with this. */
    if (CS->isInlineAsm())
        return;

    /* Indirect external calls are handled differently (wrapped in new function
     * that does the masking) */
    if (!F)
        return;

    if (!F->isDeclaration()) /* not external */
        return;

    // FIXME: use subclasses of CallInst here
    if (F->getName().startswith("llvm.eh.") ||
        F->getName().startswith("llvm.dbg.") ||
        F->getName().startswith("llvm.lifetime."))
        return;

    checkPointerArgs(CS);
}

void CheckAddrSpace::instrumentCallExtWrap(CallSite *CS) {
    Function *F = CS->getCalledFunction();
    if (CS->isInlineAsm() || !F)
        return;

    if (F->getName() != "_E__pr_info" && /* sphinx3 vfprintf wrapper */
        F->getName() != "_ZN12pov_frontend13MessageOutput6PrintfEiPKcz" && /* povray vsnprintf wrapper */
        F->getName() != "_ZN8pov_base16TextStreamBuffer6printfEPKcz" && /* povray vsnprintf wrapper */
        F->getName() != "_ZN3pov10Debug_InfoEPKcz" && /* povray vsnprintf wrapper */
        F->getName() != "_ZN6cEnvir9printfmsgEPKcz") /* omnetpp vsprintf wrapper */
        return;

    checkPointerArgs(CS);
}

void CheckAddrSpace::instrumentCallByval(CallSite *CS) {
    Function *F = CS->getCalledFunction();
    if (CS->isInlineAsm()) /* XXX inline asm should actually be masked? */
        return;
    if (F && F->isDeclaration()) /* external functions are handled above */
        return;

    IRBuilder<> B(CS->getInstruction());

    for (unsigned i = 0, n = CS->getNumArgOperands(); i < n; i++) {
        Value *arg = CS->getArgOperand(i);
        if (arg->getType()->isPointerTy() && CS->paramHasAttr(i + 1, Attribute::ByVal))
            checkPointer(arg, B);
    }
}

void CheckAddrSpace::checkNestedPointers(Value *val, CompositeType *elTy,
        std::vector<Value*> &indices, IRBuilder<> &B) {
    unsigned n = elTy->isStructTy() ?
        cast<StructType>(elTy)->getNumElements() :
        cast<ArrayType>(elTy)->getNumElements();

    for (unsigned i = 0; i < n; i++) {
        Type *ty = elTy->getTypeAtIndex(i);

        if (ty->isPointerTy()) {
            DEBUG_LINE("masking nested pointer of type " << *ty << " in value: " << *val);
            indices.push_back(B.getInt32(i));
            Value *ptr = B.CreateInBoundsGEP(val, indices);
            indices.pop_back();
            checkPointer(B.CreateLoad(ptr), B);
        }
        else if (ty->isAggregateType()) {
            indices.push_back(B.getInt32(i));
            checkNestedPointers(val, cast<CompositeType>(ty), indices, B);
            indices.pop_back();
        }
    }
}

void CheckAddrSpace::instrumentCallExtNestedPtrs(CallSite *CS) {
    static std::map<StringRef, std::vector<unsigned>> whitelist = {
        /* inlined std::list::push_back */
        {"_ZNSt8__detail15_List_node_base7_M_hookEPS0_", {1}},
        /* inlined std::string += std::string */
        {"_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_appendEPKcm", {0}}
    };

    Function *F = CS->getCalledFunction();
    if (!F)
        return;

    auto it = whitelist.find(F->getName());
    if (it == whitelist.end())
        return;

    assert(F->isDeclaration());
    IRBuilder<> B(CS->getInstruction());
    std::vector<Value*> indices = {B.getInt64(0)};

    for (unsigned i : it->second) {
        Value *arg = CS->getArgOperand(i);
        Type *elTy = cast<PointerType>(arg->getType())->getElementType();
        assert(elTy->isAggregateType());
        DEBUG_LINE("check nested pointers in arg " << i << " of:" << *CS->getInstruction());
        checkNestedPointers(arg, cast<CompositeType>(elTy), indices, B);
    }
}

void CheckAddrSpace::instrumentCmpPtr(CmpInst *ins) {
    Value *arg1 = ins->getOperand(0);
    Value *arg2 = ins->getOperand(1);
    assert(arg1->getType()->isPointerTy() == arg2->getType()->isPointerTy());
    if (!arg1->getType()->isPointerTy())
        return;

    IRBuilder<> B(ins);
    checkPointer(arg1, B);
    checkPointer(arg2, B);
}

/*
 * Mask out metadata bits in pointers when a pointer is accessed. It does not
 * mask out the overflow bit, so out-of-bound accesses will cause a fault.
 */
void CheckAddrSpace::instrumentMemAccess(Instruction *ins) {
    int ptrOperand = isa<StoreInst>(ins) ? 1 : 0;
    Value *ptr = ins->getOperand(ptrOperand);
    // TODO: don't mask if isa<ConstantExpr>(ptrOperand)

    IRBuilder<> B(ins);
    checkPointer(ptr, B);

    /* Also mask writes of pointers to externs (e.g., environ). */
    /* TODO: we don't have to mask the ptr above if global value */
    GlobalVariable *gv = dyn_cast<GlobalVariable>(ptr->stripPointerCasts());
    if (isa<StoreInst>(ins) && gv && !gv->hasInitializer() && gv->getType()->isPointerTy())
        checkPointer(ins->getOperand(0), B);
}

bool CheckAddrSpace::runOnFunction(Function &F) {
    if (F.getName() == "initialize_global_metapointers")
        return false;

    ReinterpretedPointers *ReintPtrs = getAnalysisIfAvailable<ReinterpretedPointers>();
    std::vector<Instruction*> MemoryAccesses;

    for (Instruction &I : instructions(F)) {
        if (isa<StoreInst>(I) || isa<LoadInst>(I)) {
            MemoryAccesses.push_back(&I);
        }
        if (ReintPtrs && ReintPtrs->hasNullTagUsers(&I)) {
            instrumentPtrInt(&I);
        }
    }

    for (Instruction &I : instructions(F)) {
        if (isa<CallInst>(I) || isa<InvokeInst>(I)) {
            CallSite CS(&I);
            instrumentCallExt(&CS);
            instrumentCallExtWrap(&CS);
            instrumentCallByval(&CS);
            instrumentCallExtNestedPtrs(&CS);
        }
        else ifcast(CmpInst, Cmp, &I) {
            instrumentCmpPtr(Cmp);
        }
    }

    for (Instruction *Access : MemoryAccesses)
        instrumentMemAccess(Access);

    return true;
}

void CheckAddrSpace::instrumentPtrInt(Instruction *I) {
    IRBuilder<> B(getInsertPointAfter(I));
    checkPointer(I, B);
}

static Function *createCheckFunc(Module &M) {
    LLVMContext &Ctx = M.getContext();
    Type *VoidTy = Type::getVoidTy(Ctx);
    Type *i32Ty = Type::getInt32Ty(Ctx);
    Type *i64Ty = Type::getInt64Ty(Ctx);
    Type *i8PtrTy = Type::getInt8Ty(Ctx)->getPointerTo();

    FunctionType *PrintfTy = FunctionType::get(i32Ty, i8PtrTy, true);
    Function *Printf = cast<Function>(M.getOrInsertFunction("printf", PrintfTy));

    Type *ArgTypes[] = {i64Ty, i64Ty};
    FunctionType *FnTy = FunctionType::get(VoidTy, ArgTypes, false);
    Function *F = createNoInstrumentFunction(M, FnTy, "checkptr", true);

    BasicBlock *Entry = BasicBlock::Create(F->getContext(), "entry", F);
    BasicBlock *Trap = BasicBlock::Create(F->getContext(), "trap", F);
    BasicBlock *Exit = BasicBlock::Create(F->getContext(), "exit", F);

    auto it = F->getArgumentList().begin();
    Value *PtrInt = &*it++;
    Value *CheckID = &*it;

    IRBuilder<> B(Entry);
    Value *Cond = B.CreateICmpUGT(PtrInt, B.getInt64(getAddressSpaceMask()));
    B.CreateCondBr(Cond, Trap, Exit);

    B.SetInsertPoint(Trap);
    Value *Format = B.CreateGlobalStringPtr(
            "nonzero upper bits in pointer %llx (check %llu)\n",
            "checkptr_error");
    Value *PrintfArgs[] = {Format, PtrInt, CheckID};
    B.CreateCall(Printf, PrintfArgs);
    B.CreateCall(Intrinsic::getDeclaration(&M, Intrinsic::trap));
    B.CreateUnreachable();

    B.SetInsertPoint(Exit);
    B.CreateRetVoid();

    return F;
}

bool CheckAddrSpace::initializeModule(Module &M) {
    CheckFunc = createCheckFunc(M);
    return true;
}
