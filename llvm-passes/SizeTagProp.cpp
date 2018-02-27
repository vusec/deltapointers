#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

#include <set>
#include <map>

#define DEBUG_TYPE "size-tag-prop"

#include "utils/Common.h"
#include "utils/CustomFunctionPass.h"
#include "AddressSpace.h"
#include "SafeAllocs.h"
#include "SafeAllocsOld.h"
#include "ReinterpretedPointers.h"
#include "LibPtrRet.h"

using namespace llvm;

enum ArithCheckMode { nocheck, corrupt, branch };

static cl::opt<bool> EnablePtrArith("sizetags-enable-ptr-arith",
        cl::desc("Enable pointer arithmetic propagation to metadata bits"),
        cl::init(true));

static cl::opt<bool> EnableMemIntrinsics("sizetags-enable-mem-intrinsics",
        cl::desc("Enable checks on memory intrinsics (e.g., memcpy)"),
        cl::init(true));

static cl::opt<bool> SubtractionArith("sizetags-sub-arith",
        cl::desc("Use pointer subtraction for non-constant pointer arithmetic propagation"),
        cl::init(false));

static cl::opt<enum ArithCheckMode> CheckPtrArithOverflow("check-ptr-arith-overflow",
        cl::desc("Add overflow checks to GEPs with positive or dynamic offsets:"),
        cl::values(
            clEnumValN(nocheck, "none", "No overflow check (default)"),
             clEnumVal(corrupt,         "Corrupt pointer on overflow (replace with NULL) using setcc instructions"),
             clEnumVal(branch,          "Branch to error code on overflow"),
            clEnumValEnd),
        cl::init(nocheck));

// This is only necessary for dealII in SPEC, and adds minor runtime overhead
static cl::opt<bool> CheckPtrArithUnderflow("check-ptr-arith-underflow",
        cl::desc("Add runtime checks on zero metadata (implemented as cmov on x86) at negative GEPs to avoid underflows"),
        cl::init(true));

static cl::opt<bool> DisallowUnalignedAccess("sizetags-no-unaligned",
        cl::desc("Disallow unaligned access by adding (derefsize - 1) to the size tag before masking at dereference"),
        cl::init(false));

struct SizeTagProp : public CustomFunctionPass {
    static char ID;
    SizeTagProp() : CustomFunctionPass(ID) {}

    virtual void getAnalysisUsage(AnalysisUsage &AU) const;

private:
    const DataLayout *DL;
    Function *StrBufSizeFunc;
    Function *NewStrtokFunc;
    Function *AddWithOverflowFunc;
    Function *TrapFunc;
    SafeAllocsBase *SafeAlloc;
    DominatorTree *DT;
    DenseMap<Function*, BasicBlock*> ErrorBlocks;
    DenseMap<Value*, GetElementPtrInst*> ReplacedPtrArithReverse;
    DenseMap<GetElementPtrInst*, uint64_t> DerefBytes;

    bool hasNegativeOffset(GetElementPtrInst *GEP);
    bool propagatePtrMetadata(Instruction *I);
    bool instrumentPtrArith(GetElementPtrInst *Gep);
    bool instrumentDeref(Instruction *I);
    bool instrumentMemIntrinsic(Instruction *I);
    bool isVtableGep(GetElementPtrInst *Gep);
    BasicBlock *getOrCreateErrorBlock(Function *F);

    bool moveUpOffsetInsts(GetElementPtrInst *CheckGEP,
                           GetElementPtrInst *OffsetGEP,
                           Instruction *InsertPt);
    uint64_t getSmallestDerefSize(Value *Ptr);

    bool runOnFunction(Function &F) override;
    bool initializeModule(Module &M) override;
};

char SizeTagProp::ID = 0;
static RegisterPass<SizeTagProp> X("size-tag-prop",
        "Propagate sizetags metadata to return values on stdlib functions");

STATISTIC(NLibCall,                 "Number of libcalls instrumented: total");
STATISTIC(NIgnore,                  "Number of libcalls instrumented: Ignore");
STATISTIC(NCopyFromArg,             "Number of libcalls instrumented: CopyFromArg");
STATISTIC(NPtrDiff,                 "Number of libcalls instrumented: PtrDiff");
STATISTIC(NRetSizeStatic,           "Number of libcalls instrumented: RetSizeStatic");
STATISTIC(NStrlen,                  "Number of libcalls instrumented: Strlen");
STATISTIC(NStrtok,                  "Number of libcalls instrumented: Strtok");
STATISTIC(NGep,                     "Number of ptr arith instrumented: total");
STATISTIC(NNoCheck,                 "Number of ptr arith instrumented: no check (constant positive offset)");
STATISTIC(NUnderflowCheck,          "Number of ptr arith instrumented: underflow check");
STATISTIC(NOverflowCheck,           "Number of ptr arith instrumented: overflow check (total)");
STATISTIC(NDynamicOverflowCheck,    "Number of ptr arith instrumented: overflow check (dynamic offset)");
STATISTIC(NMemIntrinsic,            "Number of memory intrinsics instrumented");
STATISTIC(NMovedOffsets,            "Number of ptr arith offsets moved for preempted bound checks");

void SizeTagProp::getAnalysisUsage(AnalysisUsage &AU) const {
    AU.addPreserved<SafeAllocs>();
    AU.addPreserved<SafeAllocsOld>();
    AU.addPreserved<ReinterpretedPointers>();
    AU.addUsedIfAvailable<SafeAllocs>();
    AU.addUsedIfAvailable<SafeAllocsOld>();
    AU.addRequired<DominatorTreeWrapperPass>();
}

/* Copy size directly from one of input arguments. */
static std::map<std::string, unsigned int> CopyFromArgList = {
    { "getcwd", 0 },
    { "realpath", 1 },
    { "strcat", 0 },
    { "strncat", 0 },
    { "gcvt", 2 },
    { "strcpy", 0 },
    { "strncpy", 0 },
    { "fgets", 0 },
    { "gets", 0 },
    { "tmpnam", 0 }, /* XXX unless NULL is passed */
    { "__dynamic_cast", 0 },

    { "_ZNSt13basic_filebufIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode", 0 }, /* std::basic_filebuf::open */
    { "_ZNSt9basic_iosIcSt11char_traitsIcEE5rdbufEPSt15basic_streambufIcS1_E", 0 }, /* std::basic_streambuf::rdbuf */
    { "_ZNSo3putEc", 0 }, /* std::basic_ostream::put */
    { "_ZNSo5flushEv", 0 }, /* std::basic_ostream::flush */
    { "_ZNSo5writeEPKcl", 0 }, /* std::basic_ostream::write */
    { "_ZNSo9_M_insertIbEERSoT_", 0 }, /* std::basic_ostream::_M_insert(bool) */
    { "_ZNSo9_M_insertIdEERSoT_", 0 }, /* std::basic_ostream::_M_insert(double) */
    { "_ZNSo9_M_insertIlEERSoT_", 0 }, /* std::basic_ostream::_M_insert(long) */
    { "_ZNSo9_M_insertImEERSoT_", 0 }, /* std::basic_ostream::_M_insert(unsigned long) */
    { "_ZNSo9_M_insertIPKvEERSoT_", 0 }, /* std::basic_ostream::_M_insert(void const*) */
    { "_ZNSi10_M_extractIfEERSiRT_", 0 }, /* std::basic_istream::_M_extract(float&) */
    { "_ZNSi10_M_extractIdEERSiRT_", 0 }, /* std::basic_istream::_M_extract(double&) */
    { "_ZNSolsEi", 0 }, /* std::basic_ostream::operator<<(int) */
    { "_ZNSolsEl", 0 }, /* std::basic_ostream::operator<<(long)  */
    { "_ZNSolsEd", 0 }, /* std::basic_ostream::operator<<(double)  */
    { "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc", 0 }, /* ostream::operator<<  */
    { "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_c", 0 }, /* std::basic_ostream::operator<<  */
    { "_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_PS3_", 0 }, /* std::operator>>(std::basic_istream&, char*) */
    { "_ZNSolsEPFRSoS_E", 0 }, /* std::basic_ostream::operator<<  */
    { "_ZSt16__ostream_insertIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_PKS3_l", 0 }, /* std::basic_ostream::__ostream_insert */
    { "_ZNSi3getERc", 0 }, /* std::basic_istream::get */
    { "_ZNSi4readEPcl", 0 }, /* std::basic_istream::read */
    { "_ZNSi7getlineEPcl", 0 }, /* std::basic_istream::getline */
    { "_ZNSi7getlineEPclc", 0 }, /* std::basic_istream::getline */
    { "_ZNSi7putbackEc", 0 }, /* std::basic_istream::putback */
    { "_ZNSs6appendEPKcm", 0 }, /* std::basic_string::append */
    { "_ZNSs6appendERKSs", 0 }, /* std::basic_string::append */
    { "_ZNSs6assignEPKcm", 0 }, /* std::basic_string::assign */
    { "_ZNSs6assignERKSs", 0 }, /* std::basic_string::assign */
    { "_ZNSspLEPKc", 0 }, /* std::basic_string::operator+= */
    { "_ZNSolsEj", 0 }, /* std::basic_ostream::operator<<(unsigned int) */
    { "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_appendEPKcm", 0 }, /* std::basic_string::_M_append */
    { "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE10_M_replaceEmmPKcm", 0 }, /* std::basic_string::_M_replace: s = "..."; */

    /* Added for dealII -O0 */
    { "_ZNSirsERb", 0 },
    { "_ZNSirsERd", 0 },
    { "_ZNSirsERi", 0 },
    { "_ZNSirsERj", 0 },
    { "_ZNSirsERt", 0 },
    { "_ZNSolsEb", 0 },
    { "_ZNSolsEf", 0 },
    { "_ZNSolsEm", 0 },
    { "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5eraseEmm", 0 },
    { "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendERKS4_", 0 },
    { "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6assignERKS4_mm", 0 },
    { "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7replaceEmmPKc", 0 },
    { "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEPKc", 0 },
    { "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSERKS4_", 0 },
    { "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEpLEc", 0 },
    { "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEpLERKS4_", 0 },
    { "_ZSt7getlineIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE", 0 },
    { "_ZStlsIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_St13_Setprecision", 0 },
    { "_ZStlsIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_St5_Setw", 0 },
    { "_ZStlsIcSt11char_traitsIcESaIcEERSt13basic_ostreamIT_T0_ES7_RKNSt7__cxx1112basic_stringIS4_S5_T1_EE", 0 },
    { "_ZStrsIcSt11char_traitsIcEERSt13basic_istreamIT_T0_ES6_RS3_", 0 },
    { "_ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE", 0 },

    { "_ZSt18_Rb_tree_decrementPKSt18_Rb_tree_node_base", 0 }, /* std::_Rb_tree_decrement */
    { "_ZSt18_Rb_tree_decrementPSt18_Rb_tree_node_base", 0 }, /* std::_Rb_tree_decrement */
    { "_ZSt18_Rb_tree_incrementPKSt18_Rb_tree_node_base", 0 }, /* std::_Rb_tree_increment */
    { "_ZSt18_Rb_tree_incrementPSt18_Rb_tree_node_base", 0 }, /* std::_Rb_tree_increment */
    { "_ZSt28_Rb_tree_rebalance_for_erasePSt18_Rb_tree_node_baseRS_", 0 }, /* std::_Rb_tree_rebalance_for_erase */
};

/* Take difference between input-pointer (argument n) and output-pointer. */
static std::map<std::string, unsigned int> PtrDiffList = {
    { "strstr", 0 },
    { "strchr", 0 },
    { "strrchr", 0 },
    { "memchr", 0 },
    { "__rawmemchr", 0 },
    { "strpbrk", 0 },
    { "bsearch", 1 },
    { "__cmsg_nxthdr", 1 },
};

/* Infer from return type (usually structs) */
static std::set<std::string> RetSizeStaticList = {
    "localeconv",
    "gmtime",
    "localtime",
    "readdir",
    "fdopen",
    "fopen",
    "popen",
    "tmpfile",
    "freopen",
    "__errno_location",
    "getpwnam",
    "getgrnam",
    "gethostbyname",
    "readdir64",
    "pcre_study",


    /* TODO: these point to pointer that holds table (e.g., *table['A"]) */
    /* NOTE: they extend also -128 before pointer. */
    "__ctype_b_loc",
    "__ctype_tolower_loc",
    "__ctype_toupper_loc",
};

/* Perform run-time strlen (+1) on resulting buffer. */
static std::set<std::string> StrlenList = {
    "ctime",
    "getenv",
    "strerror",
    "strsignal",
    "__strdup",
    "crypt",
    "ttyname",
};

/* For some functions returning pointers we don't care, but list them to disable
 * warning that we're missing cases. */
static std::set<std::string> IgnoreList = {
    "opendir", /* RetSizeStatic but opaque. */
    "signal", /* Function pointer. */

    /* These return a pointer to the next exception in the chain it seems. */
    "__cxa_get_exception_ptr",
    "__cxa_begin_catch",

    /* Handled by Allocation.cpp */
    "malloc",
    "valloc",
    "_Znwj", /* new(unsigned int) */
    "_ZnwjRKSt9nothrow_t",
    "_Znwm", /* new(unsigned long) */
    "_ZnwmRKSt9nothrow_t",
    "_Znaj", /* new[](unsigned int) */
    "_ZnajRKSt9nothrow_t",
    "_Znam", /* new[](unsigned long) */
    "_ZnamRKSt9nothrow_t",
    "__cxa_allocate_exception",
    "calloc",
    "realloc",
    "reallocf",
    "mmap64", /* TODO */
    "shmat", /* TODO? */

    /* TODO should take arg1 + 1 */
    "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9_M_createERmm", /* std::basic_string::_M_create */

    /* XXX */
    "_ZNKSs5c_strEv", /* std::basic_string::c_str */

    /* Added for dealII -O0 */
    "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE3endEv",
    "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4dataEv",
    "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5beginEv",
    "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv",
    "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE7_M_dataEv",
    "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEixEm",
    "_ZNKSt9basic_iosIcSt11char_traitsIcEE5rdbufEv",
    "_ZNKSt9basic_iosIcSt11char_traitsIcEEcvPvEv",
    "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE13_M_local_dataEv",
    "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE3endEv",
    "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5beginEv",
    "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEixEm",

    "_ZNSt13basic_filebufIcSt11char_traitsIcEE5closeEv", /* std::basic_filebuf::close */

    /* PCRE */
    "pcre_compile", /* private struct */
};

static inline bool scanList(std::set<std::string> list, Function *F) {
    return list.count(F->getName().str()) > 0;
}

static inline bool scanList(std::map<std::string, unsigned int> list, Function *F, int *dat) {
    auto p = list.find(F->getName().str());
    if (p != list.end()) {
        *dat = p->second;
        return true;
    }
    return false;
}

enum LibPtr getLibPtrType(Function *F, int *dat) {
    if (scanList(StrlenList, F)) {
        return LibPtr::Strlen;
    } else if (scanList(IgnoreList, F)) {
        return LibPtr::Ignore;
    } else if (scanList(RetSizeStaticList, F)) {
        return LibPtr::RetSizeStatic;
    } else if (scanList(CopyFromArgList, F, dat)) {
        return LibPtr::CopyFromArg;
    } else if (scanList(PtrDiffList, F, dat)) {
        return LibPtr::PtrDiff;
    } else if (F->getName() == "strtok") {
        *dat = 0;
        return LibPtr::Strtok;
    } else {
        return LibPtr::None;
    }
}

static inline unsigned getValueOpcode(Value *V) {
    ifcast(Instruction, I, V)
        return I->getOpcode();
    else ifcast(Operator, Op, V)
        return Op->getOpcode();
    else
        assert(false);
    return 0;
}

/*
 * Determines if the instruction calls an external library function that returns
 * a pointer, and propagates its metadata if so.
 * StrBufSizeFunc should be a function that determines the size of a pointer,
 * and is generally strlen + 1 unless NULL is passed to it.
 * Returns true if the IR has been modified.
 */
bool SizeTagProp::propagatePtrMetadata(Instruction *I) {
    int arg;

    if (!isa<CallInst>(I) && !isa<InvokeInst>(I))
        return false;

    CallSite CS(I);
    Function *F = CS.getCalledFunction();

    if (!F || F->isIntrinsic() || !F->isDeclaration())
        return false;

    if (SafeAlloc && !SafeAlloc->needsPropagation(I))
        return false;

    enum LibPtr type = getLibPtrType(F, &arg);

    switch (type) {
        case LibPtr::Strlen:        ++NStrlen;          break;
        case LibPtr::Ignore:        ++NIgnore;          break;
        case LibPtr::RetSizeStatic: ++NRetSizeStatic;   break;
        case LibPtr::CopyFromArg:   ++NCopyFromArg;     break;
        case LibPtr::PtrDiff:       ++NPtrDiff;         break;
        case LibPtr::Strtok:        ++NStrtok;          break;
        case LibPtr::None:                              break;
    }

    if (type == LibPtr::Ignore)
        return false;

    ++NLibCall;

    if (type == LibPtr::Strtok) {
        CS.setCalledFunction(NewStrtokFunc);
        return true;
    }
    else if (type == LibPtr::None) {
        /* Sanity check that it doesn't return pointer. */
        if (F->getReturnType()->isPointerTy()) {
            LOG_LINE("Error: unhandled ext func that returns pointer: " <<
                    F->getName() << ": " << *F->getType());
            exit(1);
        }
        return false;
    }

    IRBuilder<> B(getInsertPointAfter(I));
    Value *Ptr = I;
    std::vector<User*> Users(Ptr->user_begin(), Ptr->user_end());

    Value *PtrVal = B.CreatePtrToInt(Ptr, B.getInt64Ty());
    Value *NewSize;

    if (type == LibPtr::Strlen) {
        Value *StrBufSizeArgs[] = { Ptr };
        Value *StrSize = B.CreateCall(StrBufSizeFunc, StrBufSizeArgs);
        if (ALLOWED_OOB_BYTES) {
            IntegerType *Ty = cast<IntegerType>(StrSize->getType());
            StrSize = B.CreateAdd(StrSize, ConstantInt::get(Ty, ALLOWED_OOB_BYTES));
        }
        Value *InvSz = B.CreateAnd(B.CreateNeg(StrSize), BOUND_MASK_LOW);
        NewSize = B.CreateShl(InvSz, BOUND_SHIFT);

    } else if (type == LibPtr::RetSizeStatic) {
        Type *RetTy = F->getReturnType()->getPointerElementType();
        uint64_t InvSz = -(DL->getTypeStoreSize(RetTy) + ALLOWED_OOB_BYTES) & BOUND_MASK_LOW;
        NewSize = B.getIntN(PointerBits, InvSz << BOUND_SHIFT);

    } else if (type == LibPtr::CopyFromArg || type == LibPtr::PtrDiff) {
        /* These two are very similar, the only difference that PtrDiff does an
         * additional calculation on the size whereas CopyFromArg simply copies
         * it as-is. */

        IntegerType *PtrIntTy = getPtrIntTy(I->getContext());
        Value *OrigPtrVal = B.CreatePtrToInt(CS.getArgOperand(arg), PtrIntTy);
        Value *OldSize = B.CreateAnd(OrigPtrVal, TAG_MASK_HIGH);

        if (type == LibPtr::PtrDiff) {
            /* newsize = oldsize - (new_ptr - old_ptr) ==>
             * newupper = oldupper + ((new_ptr - old_ptr) << bnd_shift) */
            Value *OrigPtrMaskedVal = B.CreateAnd(OrigPtrVal, getAddressSpaceMask());
            Value *SizeDiff = B.CreateSub(PtrVal, OrigPtrMaskedVal);
            NewSize = B.CreateAdd(OldSize, B.CreateShl(SizeDiff, BOUND_SHIFT));
        } else {
            NewSize = OldSize;
        }
    }

    Value *NewPtr = B.CreateIntToPtr(B.CreateOr(PtrVal, NewSize), Ptr->getType());
    for (User *U : Users)
        U->replaceUsesOfWith(Ptr, NewPtr);

    return true;
}

bool SizeTagProp::isVtableGep(GetElementPtrInst *Gep) {
    Value *SrcPtr = Gep->getPointerOperand();
    if (SrcPtr->hasName() && SrcPtr->getName().startswith("vtable")) {
        //DEBUG_LINE("Ignoring vtable GEP: " << *Gep);
        return true;
    }
    if (Gep->getNumIndices() == 1) {
        Value *FirstOp = Gep->getOperand(1);
        if (FirstOp->hasName() &&
            FirstOp->getName().startswith("vbase.offset")) {
            //DEBUG_LINE("Ignoring vbase GEP: " << *Gep);
            return true;
        }
    }

    ifcast(GlobalVariable, GV, SrcPtr)
        if (GV->getName().startswith("_ZTV")) {
            //DEBUG_LINE("Ignoring GV vtable GEP: " << *Gep);
            return true;
        }

    return false;
}

#if 0
static bool hasNonDereferencingUser(Value *Ptr, User *Ignore) {
    for (User *U : Ptr->users()) {
        if (U == Ignore)
            continue;
        if (isa<LoadInst>(U))
            continue;
        ifcast(StoreInst, SI, U) {
            if (SI->getValueOperand() != Ptr)
                continue;
        }
        return true;
    }
    return false;
}
#endif

bool SizeTagProp::hasNegativeOffset(GetElementPtrInst *Gep) {
    // Negative offsets are trivial
    APInt ConstOffset(PointerBits, 0);
    if (Gep->accumulateConstantOffset(*DL, ConstOffset))
        return ConstOffset.isNegative();

    // For synamid offsets, look for the pattern "gep %base, (sub 0, %idx)"
    // XXX this is best-effort and may not catch all cases
    for (int i = 1, l = Gep->getNumOperands(); i < l; i++) {
        Value *Index = Gep->getOperand(i);
        ifncast(Instruction, I, Index)
            continue;
        if (I->getOpcode() != Instruction::Sub)
            continue;
        ifncast(ConstantInt, PossibleZero, I->getOperand(0))
            continue;
        if (PossibleZero->getSExtValue() == 0)
            return true;
    }

    return false;
}

/*
 * On pointer arithmetic, replicate the operations on the metadata in upper
 * bits.
 */
bool SizeTagProp::instrumentPtrArith(GetElementPtrInst *Gep) {
    GetElementPtrInst *PreemptedGep = nullptr;

    if (SafeAlloc)
        PreemptedGep = SafeAlloc->getPreemptedOffset(Gep);

    if (!PreemptedGep) {
        /* No effect on ptr means no effect on size. */
        if (Gep->hasAllZeroIndices())
            return false;

        /* Safe allocations are not masked, so should not be tagged. */
        if (SafeAlloc && !SafeAlloc->needsPropagation(Gep))
            return false;

        /* We want to skip GEPs on vtable stuff, as they shouldn't be able to
         * overflow, and because they don't have metadata normally negative
         * GEPs fail on these. */
        if (isVtableGep(Gep))
            return false;
    }

    /* TODO: we cannot support GEPs operating on vectors. */
    if (Gep->getType()->isVectorTy()) {
        LOG_LINE("Warning: ignoring GEP on vector: " << *Gep);
        return false;
    }

    std::string Prefix = Gep->hasName() ? Gep->getName().str() + "." : "";
    IRBuilder<> B(getInsertPointAfter(Gep));
    std::vector<User*> Users(Gep->user_begin(), Gep->user_end());
    IntegerType *PtrIntTy = getPtrIntTy(Gep->getContext());

    /* NOTE: further optimization: if only last index non-zero we can create a
     * new GEP instead of all below, which may be better for optimizer? */

    Instruction *PtrInt = cast<Instruction>(B.CreatePtrToInt(Gep, PtrIntTy, Prefix + "int"));

    /* Generate calculation of offset (for every idx, multiply element size by
     * element idx, and add all together). IRBuilder does proper constant
     * folding on this, meaning that if the entire offset is known at compile
     * time, no calculation will be present in IR. */
    Value *Diff;
    ConstantInt *ConstOffset = nullptr;

    APInt ConstOffsetVal(PointerBits, 0);
    if (Gep->accumulateConstantOffset(*DL, ConstOffsetVal))
        ConstOffset = B.getInt(ConstOffsetVal);

    if (PreemptedGep) {
        APInt PreemptedOffset(PointerBits, 0);
        if (PreemptedGep->accumulateConstantOffset(*DL, PreemptedOffset)) {
             Diff = ConstantInt::getSigned(PtrIntTy, PreemptedOffset.getSExtValue());
        } else {
            // Move up instructions that are needed for the merged offset
            // calculation but are defined later than the GEP that does the check
            if (moveUpOffsetInsts(Gep, PreemptedGep, PtrInt)) {
                NMovedOffsets++;

                // Offset instructions are inserted between the gep and the gep's
                // ptrint so that we retreive the insertion point after the
                // offsets. Set the insertion point and move the ptrint definition
                // to directly after the gep for readaibility.
                B.SetInsertPoint(getInsertPointAfter(PtrInt));
                PtrInt->removeFromParent();
                PtrInt->insertAfter(Gep);
            }
            Diff = EmitGEPOffset(&B, *DL, PreemptedGep);
        }
    }
    else if (ConstOffset) {
        Diff = ConstOffset;
    }
    else if (SubtractionArith) {
        Value *Base = Gep->getPointerOperand();
        Value *BaseInt = B.CreatePtrToInt(Base, PtrIntTy, Prefix + "baseint");
        Diff = B.CreateSub(PtrInt, BaseInt, Prefix + "diff");
    }
    else {
        Diff = EmitGEPOffset(&B, *DL, Gep);
    }

    Value *Shifted = B.CreateShl(Diff, BOUND_SHIFT, Prefix + "shifted");
    Value *AddOffset = Shifted;
    Value *PtrAdd;
    Constant *ZeroPtr = B.getIntN(PointerBits, 0);

    /* For known negative offsets, insert a check if the pointer indeed has
     * metadata, and don't do a zero metadata addition if this is the case. */
    if (CheckPtrArithUnderflow && hasNegativeOffset(Gep)) {
        // TODO: don't insert check if pointer operand certainly has metadata
        //       (if we can find the tag, i.e., if it is or'ed with a const)

        // meta = ptr >> BOUND_SHIFT  // XXX mask away overflow bit here?
        // hasmeta = meta != 0
        //Value *Meta = B.CreateLShr(PtrInt, BOUND_SHIFT, Prefix + "meta");
        //Value *HasMeta = B.CreateICmpNE(Meta, Zero, Prefix + "hasmeta");

        // hasmeta = ptr > ADDRSPACE_MASK
        // addoffset = hasmeta ? (offset << BOUND_SHIFT) : 0  // select
        Value *Zero = ConstantInt::get(PtrIntTy, 0);
        Value *Mask = ConstantInt::get(PtrIntTy, getAddressSpaceMask());
        Value *OrigPtrInt = B.CreatePtrToInt(Gep->getOperand(0), PtrIntTy, Prefix + "origptrint");
        Value *HasMeta = B.CreateICmpUGT(OrigPtrInt, Mask, Prefix + "hasmeta");
        AddOffset = B.CreateSelect(HasMeta, Shifted, Zero, Prefix + "offset");
        PtrAdd = B.CreateAdd(PtrInt, AddOffset, Prefix + "added");
        ++NUnderflowCheck;
    }
    /* For positive GEPs, replace the GEP with a nullptr if the carry flag is
     * set after the operation.
     * For dynamic GEPs, check if the offset is positive and if the operation
     * overflows. */
    else if (CheckPtrArithOverflow != nocheck && !(ConstOffset && ConstOffset->isNegative())) {
        Value *OAdd = B.CreateCall(AddWithOverflowFunc, {PtrInt, AddOffset}, Prefix + "oadd");
        Value *Result = B.CreateExtractValue(OAdd, 0, Prefix + "added");
        Value *Overflow = B.CreateExtractValue(OAdd, 1, Prefix + "overflow");
        Value *NotNegativeAndOverflow = Overflow;
        if (!ConstOffset) {
            Value *Positive = B.CreateICmpSGT(Diff, ZeroPtr, Prefix + "positive");
            NotNegativeAndOverflow = B.CreateAnd(Positive, Overflow, Prefix + "both");
            ++NDynamicOverflowCheck;
        }

        switch (CheckPtrArithOverflow) {
            /* Branch to trap code if the operation overflows */
            case branch: {
                // FIXME: what was hasNonDereferencingUser for again?
                //if (hasNonDereferencingUser(Gep, cast<User>(PtrInt))) {
                    // Split on condition
                    BasicBlock *BB = Gep->getParent();
                    BasicBlock *Succ = BB->splitBasicBlock(B.GetInsertPoint(), Prefix + "fallthru");

                    // Replace unconditional jump with conditional branch
                    BB->getTerminator()->eraseFromParent();
                    B.SetInsertPoint(BB);
                    B.CreateCondBr(NotNegativeAndOverflow, getOrCreateErrorBlock(BB->getParent()), Succ);

                    // Reset insert point
                    B.SetInsertPoint(&*Succ->begin());

                    PtrAdd = Result;
                    break;
                //}
                // fall through to create select instruction if there is no
                // non-dereferencing user
            }
            /* Nullify the result if the operation overflows */
            case corrupt:
                PtrAdd = B.CreateSelect(NotNegativeAndOverflow, ZeroPtr, Result, Prefix + "added");
                break;
            case nocheck:
                break;
        }

        ++NOverflowCheck;
    }
    /* Default: add the offset to the metadata bits */
    else {
        PtrAdd = B.CreateAdd(PtrInt, AddOffset, Prefix + "added");
        ++NNoCheck;
    }

    // TODO: try to make the final ptr, instead of the offset, a select inst
    // (and measure performance for both)
    Value *NewPtr = B.CreateIntToPtr(PtrAdd, Gep->getType(), Prefix + "newptr");
    ++NGep;

    // TODO: check if this is optimized in asm

    for (User *U : Users)
        U->replaceUsesOfWith(Gep, NewPtr);

    // Maintain mapping for instrumentDeref
    ReplacedPtrArithReverse[NewPtr] = Gep;

    return true;
}

/*
 * On dereference, add (derefsize - 1) to the size tag to avoid unaligned OoB
 * accesses,
 */
bool SizeTagProp::instrumentDeref(Instruction *I) {
    int PtrOperand = isa<LoadInst>(I) ? 0 : 1;
    Value *Ptr = I->getOperand(PtrOperand);

    if (SafeAlloc && !SafeAlloc->needsMask(I, Ptr))
        return false;

    Type *Ty = isa<LoadInst>(I) ? I->getType() :
        cast<StoreInst>(I)->getValueOperand()->getType();
    assert(Ty->isSized());
    uint64_t Size = DL->getTypeStoreSize(Ty);
    uint64_t AlignBytes = Size - 1;

    // If this GEP takes the offset from a subsequent GEP, then take the number
    // of alignment bytes from the accompanying load/store as well
    if (SafeAlloc) {
        if (GetElementPtrInst *Gep = ReplacedPtrArithReverse.lookup(Ptr)) {
            if (uint64_t DerefSize = DerefBytes.lookup(Gep)) {
                uint64_t PreemptedAlignBytes = DerefSize - 1;
                if (PreemptedAlignBytes < AlignBytes) {
                    DEBUG_LINE("use " << PreemptedAlignBytes << " instead of " <<
                               AlignBytes << " alignment bytes because of preemption:");
                    DEBUG_LINE(*I);
                    AlignBytes = PreemptedAlignBytes;
                }
            }
        }
    }

    if (AlignBytes == 0)
        return false;

    IRBuilder<> B(I);
    std::string Prefix = Ptr->hasName() ? Ptr->getName().str() + "." : "";
    Value *AsInt = B.CreatePtrToInt(Ptr, B.getIntNTy(PointerBits), Prefix + "int");
    Value *Align = B.CreateAdd(AsInt, B.getIntN(PointerBits, AlignBytes << BOUND_SHIFT), Prefix + "align");
    Value *Aligned = B.CreateIntToPtr(Align, Ptr->getType(), Prefix + "aligned");
    I->setOperand(PtrOperand, Aligned);

    return true;
}

BasicBlock *SizeTagProp::getOrCreateErrorBlock(Function *F) {
    auto it = ErrorBlocks.find(F);
    if (it != ErrorBlocks.end())
        return it->second;

    BasicBlock *BB = BasicBlock::Create(F->getContext(), "oob_error", F);
    IRBuilder<> B(BB);

    // TODO
    //Value *Fd = B.getInt32(2);
    //Value *Format = B.CreateGlobalStringPtr("OoB pointer detected in %s\n", "oob_error");
    //setNoInstrument(Format);
    //B.CreateCall(Printf, {Fd, Format, });

    B.CreateCall(TrapFunc);
    B.CreateUnreachable();

    ErrorBlocks[F] = BB;
    return BB;
}

bool SizeTagProp::instrumentMemIntrinsic(Instruction *I) {
    IRBuilder<> B(I);
    IntegerType *PtrIntTy = getPtrIntTy(I->getContext());

    Value *Length;
    Use *PtrArg1Use, *PtrArg2Use = NULL;
    ifcast(MemIntrinsic, MI, I) {
        Length = MI->getLength();
        PtrArg1Use = &MI->getRawDestUse();
        ifcast(MemTransferInst, MTI, MI) {
            PtrArg2Use = &MTI->getRawSourceUse();
        }
    } else ifcast(CallInst, CI, I) {
        if (CI->getCalledFunction()->getName() == "memcmp") {
            Length = CI->getArgOperand(2);
            PtrArg1Use = &CI->getArgOperandUse(0);
            PtrArg2Use = &CI->getArgOperandUse(1);
        } else {
            errs() << "Unhandled call: " << *CI << "\n";
            llvm_unreachable("unhandled call");
        }
    } else {
        errs() << "Unhandled intrinsic inst: " << *I << "\n";
        llvm_unreachable("unhandled inst");
    }

    Value *AccessedLength = B.CreateSub(Length, ConstantInt::get(Length->getType(), 1), "accessedlen");
    Value *ShiftedLength = B.CreateShl(AccessedLength, BOUND_SHIFT, "shiftedlen");

    Value *Ptr1 = PtrArg1Use->get();
    Value *Ptr1Int = B.CreatePtrToInt(Ptr1, PtrIntTy, "ptr1.int");
    Value *Ptr1Add = B.CreateAdd(Ptr1Int, ShiftedLength, "ptr1.add");
    Value *Ptr1New = B.CreateIntToPtr(Ptr1Add, Ptr1->getType(), "ptr1.new");
    PtrArg1Use->set(Ptr1New);

    if (PtrArg2Use) {
        Value *Ptr2 = PtrArg2Use->get();
        Value *Ptr2Int = B.CreatePtrToInt(Ptr2, PtrIntTy, "ptr2.int");
        Value *Ptr2Add = B.CreateAdd(Ptr2Int, ShiftedLength, "ptr2.add");
        Value *Ptr2New = B.CreateIntToPtr(Ptr2Add, Ptr2->getType(), "ptr2.new");
        PtrArg2Use->set(Ptr2New);
    }

    ++NMemIntrinsic;
    return true;
}

bool SizeTagProp::runOnFunction(Function &F) {
    bool Changed = false;
    SmallVector<GetElementPtrInst*, 8> Geps;
    SmallVector<Instruction*, 8> Derefs;
    SmallVector<Instruction*, 8> MemIntrinsics;

    DT = &getAnalysis<DominatorTreeWrapperPass>(F).getDomTree();
    ReplacedPtrArithReverse.clear();
    DerefBytes.clear();

    for (Instruction &I : instructions(F)) {
        Changed |= propagatePtrMetadata(&I);

        if (EnablePtrArith) {
            ifcast(GetElementPtrInst, Gep, &I)
                Geps.push_back(Gep);
        }

        if (DisallowUnalignedAccess) {
            if (isa<LoadInst>(I) || isa<StoreInst>(I))
                Derefs.push_back(&I);
        }

        if (EnableMemIntrinsics) {
            ifcast(MemIntrinsic, MI, &I)
                MemIntrinsics.push_back(MI);
            ifcast(CallInst, CI, &I) {
                Function *CF = CI->getCalledFunction();
                if (CF && CF->hasName() && CF->getName() == "memcmp")
                    MemIntrinsics.push_back(CI);
            }
        }
    }

    // Save preempted alignment sizes for instrumentDeref
    if (SafeAlloc && !Derefs.empty()) {
        for (GetElementPtrInst *Gep : Geps) {
            if (GetElementPtrInst *PreemptedGep = SafeAlloc->getPreemptedOffset(Gep))
                DerefBytes[Gep] = getSmallestDerefSize(PreemptedGep);
        }
    }

    for (GetElementPtrInst *Gep : Geps)
        Changed |= instrumentPtrArith(Gep);

    for (Instruction *I : Derefs)
        Changed |= instrumentDeref(I);

    for (Instruction *I : MemIntrinsics)
        Changed |= instrumentMemIntrinsic(I);

    return Changed;
}

bool SizeTagProp::initializeModule(Module &M) {
    DL = &M.getDataLayout();
    StrBufSizeFunc = getNoInstrumentFunction(M, "strsize_nullsafe", false);
    NewStrtokFunc = getNoInstrumentFunction(M, "strtok", false);
    if (CheckPtrArithOverflow != nocheck) {
        Type *PtrIntTy = getPtrIntTy(M.getContext());
        AddWithOverflowFunc = Intrinsic::getDeclaration(&M,
                Intrinsic::uadd_with_overflow, PtrIntTy);
    }
    TrapFunc = Intrinsic::getDeclaration(&M, Intrinsic::trap);
    if (!(SafeAlloc = getAnalysisIfAvailable<SafeAllocs>()))
        SafeAlloc = getAnalysisIfAvailable<SafeAllocsOld>();
    ErrorBlocks.clear();
    return false;
}

bool SizeTagProp::moveUpOffsetInsts(GetElementPtrInst *CheckGEP,
                                    GetElementPtrInst *OffsetGEP,
                                    Instruction *InsertPt) {
    if (!DT->dominates(CheckGEP, OffsetGEP)) {
        // If the check gep comes after the offset gep, no instructions need to
        // be moved. Do make sure, however, that the offset is always available
        // at the check, i.e. that the offset gep dominates the check
        assert(DT->dominates(OffsetGEP, CheckGEP));
        return false;
    }

    // XXX: we could use a SCEVExpander if we don't want to move the
    // instructions. but rather duplicate their semantics at the check gep
    // (this makes little sense if the distance between the geps is small and
    // the result can be kept in a register)
    //SCEVExpander Expander(*SE, *DL, "offset_expander");
    //Type *Ty = DL->getIntPtrType(CheckGEP->getContext());
    //Value *Offset = Expander.expandCodeFor(getGEPOffsetSCEV(OffsetGEP), Ty, CheckGEP);

    // Move up any instructions that are needed for calculating the offset
    SmallVector<Instruction*, 4> MoveList, Worklist;

    for (Use &U : OffsetGEP->operands()) {
        ifcast(Instruction, UI, U.get())
            Worklist.push_back(UI);
    }

    // Collect instructions to move by traversing operands
    while (!Worklist.empty()) {
        Instruction *I = Worklist.pop_back_val();

        if (!DT->dominates(CheckGEP, I))
            continue;

        // Avoid endless recursion
        assert(!isa<PHINode>(I));

        MoveList.push_back(I);

        for (Use &U : I->operands()) {
            ifcast(Instruction, UI, U.get())
                Worklist.push_back(UI);
        }
    }

    // Preserve order of occurrence
    // TODO: remove this? not sure if it's useful
    //std::sort(MoveList.begin(), MoveList.end(),
    //        [&](Instruction *A, Instruction *B) -> int {
    //            if (A == B)
    //                return 0;
    //            if (DT->dominates(A, B))
    //                return 1;
    //            assert(DT->dominates(B, A));
    //            return -1;
    //        });

    // Do the actual moving. The list is in reverse order, so move the
    // insertion point after every move.
    for (Instruction *I : MoveList) {
        I->moveBefore(InsertPt);
        InsertPt = I;
    }

    return !MoveList.empty();
}

uint64_t SizeTagProp::getSmallestDerefSize(Value *Ptr) {
    uint64_t MinDerefSize = 0;
    bool Unmatching = false;
    assert(Ptr->getNumUses() > 0);

    for (User *U : Ptr->users()) {
        assert(isa<LoadInst>(U) || isa<StoreInst>(U));
        Type *Ty = isa<LoadInst>(U) ? U->getType() :
            cast<StoreInst>(U)->getValueOperand()->getType();
        assert(Ty->isSized());
        uint64_t DerefSize = DL->getTypeStoreSize(Ty);

        if (MinDerefSize && DerefSize != MinDerefSize)
            Unmatching = true;

        if (!MinDerefSize || DerefSize < MinDerefSize)
            MinDerefSize = DerefSize;
    }

    if (Unmatching) {
        LOG_LINE("warning: preempted GEP is dereferenced with different sizes, could miss an unaligned access here:");
        LOG_LINE(*Ptr);
    }

    return MinDerefSize;
}
