# fdo

Implementation on the FIDO Device Onboarding protocol FDO:

<https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v1.1-20220419/FIDO-Device-Onboard-PS-v1.1-20220419.html>

## Running

You will need some dependencies and use the `just` command runner:

```sh
# Sync other repos
# This will pull and build the go-fdo-server, this step is not greate since could fail if upstream
# changes the commands to start the containers
just sync
# Build some tpm2 C libraries
just build-tpm2-tss
# Create keys for go-fdo-server
just setup
# Start all the servers
just serve
just halth
# Create rendevouz info
just data-create
# Device initialization
just client di
# Device initialization
# You will need to copy the guid of the device for the next step
just client di
# Start transfer ownership protocol on the server side (example GUID: 2721b5f989373f8af7892d9375aaa5b0)
just send-to0 <GUID>
# Finish the FDO on the device
just client to
```

