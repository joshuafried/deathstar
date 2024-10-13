#!/bin/bash

set -e
set -x

pushd redis
docker build -t socialnet_redis . --no-cache
popd
