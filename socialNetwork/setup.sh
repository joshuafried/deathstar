#!/bin/bash


set -e
set -x

pushd docker/thrift-microservice-deps/cpp
docker build -t thrift-microservice-deps:jammy .
popd

pushd redis
docker build -t socialnet_redis .
popd



docker build -t social-network-microservices:latest .

sudo docker network create --subnet 172.32.0.0/16 socialnet || true
