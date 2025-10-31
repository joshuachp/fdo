#!/usr/bin/env bash

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

python -c "import sys;import fileinput;sys.stdout.buffer.write(bytes.fromhex(''.join(fileinput.input(sys.argv[1:]))))" "$@"
