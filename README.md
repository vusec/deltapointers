About
=====

This repository contains the source code for the EuroSys'18 paper
"Delta Pointers: Buffer Overflow Checks Without the Checks" by Taddeus Kroes,
Koen Koning (shared first authors), Erik van der Kouwe, Herbert Bos and
Cristiano Giuffrida. The paper is available for download
[here](https://www.vusec.net/download/?t=papers/delta-pointers_eurosys18.pdf).

Delta Pointers protect programs against buffer overflows by means of
instrumentation inserted by the compiler. The inserted instrumentation inserts
and updates a so-called *delta tag* into each pointer, which records two pieces
of information: the distance of the pointer to the end of its corresponding
memory object in the virtual address space, and a single overflow bit that
indicates whether the pointer is out-of-bounds. The state of the overflow bit
is managed efficiently by arithmetic operations, without the use of any
additional branches or memory accesses. Upon dereference, the distance is taken
out of the pointer using a bitwise AND operation, but the overflow bit is left
intact. When set, this bit will cause the dereferenced pointer to become
*non-canonical*, in turn causing a general protection fault in the processor.
This way, out-of-bounds pointers are automatically rejected by the hardware.


Building and running instrumented programs
==========================================

TODO: prerequisites

This repository only contains code for LLVM passes and a small runtime library.
We use an external [infrastructure](https://github.com/vusec/instrumentation-infra)
library to plug these passes into existing build systems like that of SPEC.

First, make sure the infrastructure is up-to-date (in case you did not so a
recursive clone of this repo):

  $ git submodule update --init

The infrastructure's only hard dependency is Python 3.5. For nicer command-line
usage, install the following python packages (optional):

  $ pip3 install --user coloredlogs argcomplete

`argcomplete` enables command-line argument completion, but it needs to be
activated first (optional):

  $ eval "$(register-python-argcomplete --complete-arguments -o nospace -o default -- setup.py)"

Building/running benchmarks and dependencies is done with `setup.py` which
knows about dependencies and build scripts. The following command builds all
dependencies, the Delta Pointers passes and runtime, and some small test
programs. It then runs the runs the test programs, both without (the
`clang-lto` baseline instance) and with our instrumentation (the `deltatags`
instance):

  $ ./setup.py run --build deltatags-test clang-lto deltatags

This will take a long time, so go get some coffee and plug in your laptop
battery. The output should look somewhat like [this](TODO). For `clang-lto`,
the tests that do a buffer overflow should fail because they expect an error to
be raised. For `deltatags`, all test should succeed.

To run SPEC-CPU2006, you will need to provide your own copy of the source. You
can do so by modifying `source` and `source_type` on the relevant lines in
`setup.py`. See the relevant [documentation](TODO) for details. After
configuring `setup.py`, build and run the benchmark suite like this:

  $ ./setup.py run --build spec2006 deltatags --test

This will build and run all 19 C/C++ benchmarks with Delta Pointers
instrumentation, using the 'test' workload. To run the baseline, use
`clang-lto` instead of `deltatags`. Results will be in the SPEC installation
directory `build/targets/spec2006/install`. For a complete list of run options,
consult:

  $ ./setup.py run --help
  $ ./setup.py run spec2006 --help


Instrumenting your own program
==============================

To run instrumentation on your own programs, you can either extract the
relevant parts (`llvm-passes/` and `runtime/`) and put them into your own
repository, or you can define your own *target*. See `target.py` for an
example.


Repo orginazation
=================

The source consists of several components:

  - `llvm-passes/` LLVM passes that instrument a program at compile time. This
    is the core of our work.

  - `runtime/` A runtime library containing helper functions called by our
    instrumentation.

  - 'shrinkaddrspace/` A runtime library that shrinks the virtual address space
    of a process to an arbitrary number of bits, in order to accomodate larger
    delta tags (which is needed to support large object allocations). This
    standalone library is reused from an earlier project called Mid-Fat
    Pointers.

  - `patches/` Some patches for the SPEC-CPU2006 benchmark suite, making it
    compatible with tagged pointers.

  - `deltatags-test` A collection of toy programs that test different parts of
    the Delta Pointers implementation. `targets.py` informs the setup script
    how to build/run these programs.

  - `infra` An external repository that facilitates program instrumentation for
    common benchmarks in systems research (developed in conjunction with Delta
    Pointers). The interface into this framework is `setup.py`.

  - `setup.py` is the main tool to build/run stuff with. This is where you
    register new benchmarks (or 'targets') and hook in any custom passes of
    your own. The script has descriptive usage messages for all subcommands.

  - `instances.py` informs the setup script how to build programs with Delta
    Pointers instrumentation. If you want to add custom instrumentation passes,
    this is the place to do it.
