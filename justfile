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

# Run the container
run:
    ./scripts/run.sh

# Initialize the fdo files and container
init:
    ./scripts/clone.sh
    ./scripts/setup.sh

# Check health of servers
health:
    curl http://localhost:8041/health  # Rendezvous
    curl http://localhost:8038/health  # Manufacturing
    curl http://localhost:8043/health  # Owner

rv-create:
    curl --location --request POST 'http://localhost:8038/api/v1/rvinfo' --header 'Content-Type: text/plain' --data-raw '[{"dns":"fdo.example.com","device_port":"8041","owner_port":"8041","protocol":"http","ip":"127.0.0.1"}]'

rv-info:
    curl --location --request GET 'http://localhost:8038/api/v1/rvinfo'
