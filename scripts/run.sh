#!/usr/bin/env bash

set -exEuo pipefail

# Trap -e errors
trap 'echo "Exit status $? at line $LINENO from: $BASH_COMMAND"' ERR

$CONTAINER network create fdo-network

# Rendezvous Server
$CONTAINER run -d \
    --name fdo-rendezvous \
    --network fdo-network \
    --user 0:0 \
    -p 8041:8041 \
    -v "$FDODIR":/tmp/fdo:z \
    go-fdo-server:latest \
    --debug rendezvous 0.0.0.0:8041 \
    --db /tmp/fdo/db/rendezvous.db \
    --db-pass 'P@ssw0rd1!'

# Manufacturing Server
$CONTAINER run -d \
    --name fdo-manufacturer \
    --network fdo-network \
    --user 0:0 \
    -p 8038:8038 \
    -v "$FDODIR":/tmp/fdo:z \
    go-fdo-server:latest \
    --debug manufacturing 0.0.0.0:8038 \
    --db /tmp/fdo/db/manufacturer.db \
    --db-pass 'P@ssw0rd1!' \
    --manufacturing-key /tmp/fdo/certs/manufacturer.key \
    --owner-cert /tmp/fdo/certs/owner.crt \
    --device-ca-cert /tmp/fdo/certs/device_ca.crt \
    --device-ca-key /tmp/fdo/certs/device_ca.key

# Owner Server
$CONTAINER run -d \
    --name fdo-owner \
    --network fdo-network \
    --user 0:0 \
    -p 8043:8043 \
    -v "$FDODIR":/tmp/fdo:z \
    go-fdo-server:latest \
    --debug owner 0.0.0.0:8043 \
    --db /tmp/fdo/db/owner.db \
    --db-pass 'P@ssw0rd1!' \
    --owner-key /tmp/fdo/certs/owner.key \
    --device-ca-cert /tmp/fdo/certs/device_ca.crt
