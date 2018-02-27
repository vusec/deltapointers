#!/bin/bash
set -euo pipefail

[ $# -gt 2 ] && { echo "Usage: $0 [config-name] [run-wrapper]"; exit 1; }

suffix=""
run_wrapper=""
[ $# -ge 1 ] && suffix="-$1"
[ $# -eq 2 ] && run_wrapper="$2"

# Determine directory that script is in, so it can be invoked from anywhere.
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

fails=0
bins=`make -s bins SUFFIX="$suffix"`
for b in $bins; do
    if [ ! -f "$b" ]; then
        echo "ERROR: Binary $b not found in build dir!"
        exit 1
    fi

    bname=`basename "$b"`
    outfile="${b}.out"

    export RTS_OUTFILE_BASE="rts_${bname}_"

    if ! eval "$run_wrapper $b" &> "$outfile"; then
        echo "[FAIL] $bname"
        fails=$((fails + 1))
    else
        echo "[ OK ] $bname"
        rm "$outfile"
    fi
done

if [ $fails -gt 0 ]; then
    echo
    echo "$fails benchmark(s) failed. See binary directory for output files"
    exit 1;
fi
