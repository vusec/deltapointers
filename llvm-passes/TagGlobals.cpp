#define DEBUG_TYPE "tag-globals"

#include "utils/Common.h"
#include "AddressSpace.h"

using namespace llvm;

struct TagGlobals : public ModulePass {
    static char ID;
    TagGlobals() : ModulePass(ID) {}

    bool runOnModule(Module &M) override;
};

char TagGlobals::ID = 0;
static RegisterPass<TagGlobals> X("tag-globals",
        "Replace all internal globals with `global_tag(global) | global` "
        "(must implement global_tag in a later pass)");

STATISTIC(NTaggedGlobal, "Number of tagged globals");

/*
 * Collect global variables that can be tagged (anything except environ and
 * llvm.*).
 */
static void findGlobalsToTag(Module &M, std::vector<GlobalVariable*> &Globals) {
    for (GlobalVariable &GV : M.globals()) {
        assert(!GV.getName().startswith("tagged.") && "can only tag globals once");

        if (isNoInstrument(&GV))
            continue;

        /* Don't mask globals from libraries XXX right? */
        if (!GV.hasInitializer())
            continue;

        /* Ignore constants */
        if (GV.isConstant())
            continue;

        /* Ignore @environ bevause of getenv problems FIXME */
        //if (GV.getName() == "environ")
        //    continue;
        // Should be caught by !hasInitializer() above:
        assert(GV.getName() != "environ");

        /* Ignore intrinsics like constructor lists */
        if (GV.getName().startswith("llvm."))
            continue;

        Globals.push_back(&GV);
    }
}

/*
 * Create constructor function that replaces all globals with pointers, and
 * initializes their metapointers. Insert it in the constructor list after
 * initialize_global_metadata if it exists, or at the start of the list
 * otherwise. If no constructor list exists, create it.
 */
static Function *createGlobalTagConstructor(Module &M) {
    LLVMContext &Ctx = M.getContext();
    FunctionType *FnTy = FunctionType::get(Type::getVoidTy(Ctx), false);
    Function *F = createNoInstrumentFunction(M, FnTy, "initialize_tagged_globals", false);

    /* Add function to constructor list after @initialize_global_metadata */
    GlobalVariable *OldGlobalCtors = M.getGlobalVariable("llvm.global_ctors");
    std::vector<Constant*> Ctors;
    int index = 0;

    if (OldGlobalCtors) {
        assert(OldGlobalCtors->hasNUses(0));
        OldGlobalCtors->setName("llvm.global_ctors_old");

        ConstantArray *CA = cast<ConstantArray>(OldGlobalCtors->getInitializer());
        int i = 0;

        for (Use &I : CA->operands()) {
            Ctors.push_back(cast<Constant>(I.get()));

            if (ConstantStruct *Struct = dyn_cast<ConstantStruct>(I.get())) {
                Function *Fn = cast<Function>(Struct->getAggregateElement(1));
                if (Fn->getName() == "initialize_global_metadata")
                    index = i + 1;
            }
            i++;
        }
    }

    if (index == 0)
        DEBUG_LINE("Inserting global initializer at start of constructor list");
    else
        DEBUG_LINE("Inserting global initializer after initialize_global_metadata");

    IntegerType *i32 = Type::getInt32Ty(Ctx);
    PointerType *i8Ptr = Type::getInt8Ty(Ctx)->getPointerTo();
    StructType *StructTy = StructType::get(i32, F->getType(), i8Ptr, nullptr);
    Constant *StructMembers[] = {
        ConstantInt::getSigned(i32, -1), F, ConstantPointerNull::get(i8Ptr)
    };
    Constant *NewEntry = ConstantStruct::get(StructTy, StructMembers);
    Ctors.insert(Ctors.begin() + index, NewEntry);

    ArrayType *CtorsTy = ArrayType::get(StructTy, Ctors.size());
    new GlobalVariable(M, CtorsTy, false, GlobalValue::AppendingLinkage,
            ConstantArray::get(CtorsTy, Ctors), "llvm.global_ctors");

    if (OldGlobalCtors)
        OldGlobalCtors->eraseFromParent();

    return F;
}

bool TagGlobals::runOnModule(Module &M) {
    std::vector<GlobalVariable*> Globals;
    findGlobalsToTag(M, Globals);

    if (Globals.empty())
        return false;

    IntegerType *PtrIntTy = getPtrIntTy(M.getContext());
    FunctionType *FnTy = FunctionType::get(PtrIntTy, PtrIntTy, false);
    Function *TagGLobalFunc = createNoInstrumentFunction(M, FnTy, "global_tag", true);

    Function *F = createGlobalTagConstructor(M);
    IRBuilder<> B(BasicBlock::Create(F->getContext(), "entry", F));

    for (GlobalVariable *GV : Globals) {
        PointerType *PtrTy = GV->getType();
        GlobalVariable *TaggedGV = new GlobalVariable(M, PtrTy, false,
                GlobalValue::InternalLinkage, ConstantPointerNull::get(PtrTy),
                Twine("tagged.") + GV->getName());

        Value *PtrInt = B.CreatePtrToInt(GV, PtrIntTy, "ptrint");
        Value *Tag = B.CreateCall(TagGLobalFunc, PtrInt, "tag");
        Value *HighBits = B.CreateShl(Tag, AddressSpaceBits, "highbits");
        Value *TaggedPtrInt = B.CreateOr(PtrInt, HighBits, "taggedint");
        Value *TaggedPtr = B.CreateIntToPtr(TaggedPtrInt, PtrTy, "tagged");
        B.CreateStore(TaggedPtr, TaggedGV);
        ++NTaggedGlobal;
    }

    B.CreateRetVoid();
    return true;
}
