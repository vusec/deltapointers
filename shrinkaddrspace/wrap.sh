#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

[  $# -lt 1 ] && { echo "Usage: $0 binary [args]"; exit 1; }
prog=$1
shift
if [ ! -f $prog ]; then
    prog=`which "$prog"`
    [ ! -f $prog ] && { echo "Could not find $prog here nor in PATH"; exit 1; }
fi

prelink_dir="prelink-`echo $prog | tr / _`"
"$DIR/prelink_binary.py" --set-rpath "$prog" --preload-lib "$DIR/libpreload.so"

newprog="$prelink_dir/`basename "$prog"`"
export LD_LIBRARY_PATH="`pwd`/$prelink_dir:$LD_LIRARY_PATH"
export LD_PRELOAD="`pwd`/$prelink_dir/libpreload.so"
exec "$newprog" "$@"
