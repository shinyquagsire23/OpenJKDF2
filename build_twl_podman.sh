#!/bin/bash

# Build script for Nintendo DSi (TWL), uses podman because macOS.

BASE_IMAGE="skylyrac/blocksds:dev-latest"
LOCAL_IMAGE="blocksds_openjkdf2:latest"

if [ "$(whoami)" != "root" ]; then
        podman machine init
        podman machine start

        # TODO race condition on this
        rm -f /tmp/podman_pull_output
        echo "Checking for BlocksDS image updates..."
        if ! podman pull "$BASE_IMAGE" >/tmp/podman_pull_output 2>&1; then
            echo "Failed to pull upstream metadata."
            cat /tmp/podman_pull_output
        fi

        # If the pull output includes "Image pulled", it actually updated.
        if grep -q "Image pulled" /tmp/podman_pull_output; then
            echo "Recreating image based on new upstream"
            podman rm blocksds_openjkdf2
            podman rmi --force "$LOCAL_IMAGE"

            podman run -v $(PWD):/work -it --entrypoint /work/build_twl_podman.sh \
        --name blocksds_openjkdf2 "$BASE_IMAGE"
            if [ $? -ne 0 ]; then
                exit -1
            fi
            podman commit blocksds_openjkdf2 "$LOCAL_IMAGE"
        elif ! podman image exists "$LOCAL_IMAGE"; then
            echo "Creating new local image $LOCAL_IMAGE"

            podman rm blocksds_openjkdf2
            podman rmi --force "$LOCAL_IMAGE"

            podman run -v $(PWD):/work -it --entrypoint /work/build_twl_podman.sh \
        --name blocksds_openjkdf2 "$BASE_IMAGE"
            if [ $? -ne 0 ]; then
                exit -1
            fi
            
            podman commit blocksds_openjkdf2 "$LOCAL_IMAGE"
        else
            echo "Using existing local image $LOCAL_IMAGE"
            podman run -v $(PWD):/work -it --entrypoint /work/build_twl_podman.sh "$LOCAL_IMAGE"
        fi
        if [ $? -ne 0 ]; then
            exit -1
        fi

        exit 0
fi

DEBIAN_FRONTEND="noninteractive"
export TZ="America/Denver"

if dpkg-query -l cmake > /dev/null 2>&1; then
    echo "cmake is installed."
else
    echo "cmake is NOT installed. Installing dependencies"

    echo "${TZ}" > /etc/timezone && apt update -y && apt install -y tzdata
    if [ $? -ne 0 ]; then
        exit -1
    fi
    dpkg-reconfigure -f noninteractive tzdata
    if [ $? -ne 0 ]; then
        exit -1
    fi

    apt install -y cmake python3 python3-venv
    if [ $? -ne 0 ]; then
        exit -1
    fi
fi

cd /work && /work/build_twl.sh
if [ $? -ne 0 ]; then
    exit -1
fi