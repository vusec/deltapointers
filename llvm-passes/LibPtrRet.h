#ifndef LIB_PTR_RET_H
#define LIB_PTR_RET_H

enum LibPtr {
    None,
    Ignore,
    CopyFromArg,
    PtrDiff,
    RetSizeStatic,
    Strlen,
    Strtok,
};

enum LibPtr getLibPtrType(Function *F, int *dat);

#endif /* !LIB_PTR_RET_H */
