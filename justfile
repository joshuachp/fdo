set unstable

export CONTAINER := if which("docker") != "" {
    "docker"
} else if which("podman") != "" {
    "podman"
} else {
    error("no container runtime")
}
export FDODIR := "./.tmp/fdo"

default:
    just --list

# Initialize the fdo files and container
setup:
    ./scripts/setup.sh

sync:
    ./scripts/clone.sh
    ./scripts/build.sh

# Start the container servers
serve:
    ./scripts/serve.sh

# Check health of servers
health:
    curl --fail http://localhost:8041/health  # Rendezvous
    curl --fail http://localhost:8038/health  # Manufacturing
    curl --fail http://localhost:8043/health  # Owner

data-create:
    curl --fail --location --request POST 'http://localhost:8038/api/v1/rvinfo' --header 'Content-Type: text/plain' --data-raw '[{"dns":"localhost","device_port":"8041","owner_port":"8041","protocol":"http","ip":"127.0.0.1"}]'
    curl --fail --location --request POST 'http://localhost:8043/api/v1/owner/redirect' --header 'Content-Type: text/plain' --data-raw '[{"dns":"localhost","port":"8043","protocol":"http","ip":"127.0.0.1"}]'

data-info:
    curl --fail --location --request GET 'http://localhost:8038/api/v1/rvinfo' | jq
    curl --fail --location --request GET 'http://localhost:8043/api/v1/owner/redirect' | jq

basic-onboarding:
    ./scripts/basic-onboarding.sh

clean:
    -$CONTAINER stop fdo-rendezvous
    -$CONTAINER stop fdo-manufacturer
    -$CONTAINER stop fdo-owner
    -rm -rf ./.tmp
