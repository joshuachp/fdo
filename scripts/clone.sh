#!/usr/bin/env bash

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

if [ ! -d go-fdo-server/ ]; then
    git clone https://github.com/fido-device-onboard/go-fdo-server.git
fi
if [ ! -d go-fdo-client/ ]; then
    git clone https://github.com/fido-device-onboard/go-fdo-client.git
fi

pushd go-fdo-server/
git pull
git checkout main
popd

pushd go-fdo-client/
git pull
git checkout main
popd
