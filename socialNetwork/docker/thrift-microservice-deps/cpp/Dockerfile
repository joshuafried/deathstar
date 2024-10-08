#!/bin/bash

#ARG 
LIB_MONGOC_VERSION=1.15.0
#ARG 
LIB_THRIFT_VERSION=0.12.0
LIB_JSON_VERSION=3.6.1
LIB_JAEGER_VERSION=0.4.2
LIB_YAML_VERSION=0.6.2
LIB_OPENTRACING_VERSION=1.5.1
LIB_CPP_JWT_VERSION=1.1.1
LIB_CPP_REDIS_VERSION=4.3.1
LIB_AMQP_CPP_VERSION=4.1.4
LIB_SIMPLEAMQPCLIENT_VERSION=2.4.0
LIB_HIREDIS_VERSION=1.0.0
LIB_REDIS_PLUS_PLUS_VERSION=1.2.3

BUILD_DEPS="ca-certificates g++ cmake wget git libmemcached-dev automake bison flex libboost-all-dev libevent-dev libssl-dev libtool make pkg-config librabbitmq-dev python3-dev python3-pip python3-setuptools python3-wheel"

INST="-DCMAKE_INSTALL_PREFIX=/users/friedj/install"


set -e
set -x

sudo apt-get install -y $BUILD_DEPS


  # Install mongo-c-driver
 cd /tmp \
  && wget https://github.com/mongodb/mongo-c-driver/releases/download/${LIB_MONGOC_VERSION}/mongo-c-driver-${LIB_MONGOC_VERSION}.tar.gz \
  && tar -zxf mongo-c-driver-${LIB_MONGOC_VERSION}.tar.gz \
  && cd mongo-c-driver-${LIB_MONGOC_VERSION} \
  && mkdir -p cmake-build \
  && cd cmake-build \
  && cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_TESTS=0 -DENABLE_EXAMPLES=0 ${INST} .. \
  && make -j$(nproc) \
  && make install \
  && cd /tmp \
  && wget -O thrift-${LIB_THRIFT_VERSION}.tar.gz https://github.com/apache/thrift/archive/v${LIB_THRIFT_VERSION}.tar.gz \
  && tar -zxf thrift-${LIB_THRIFT_VERSION}.tar.gz \
  && cd thrift-${LIB_THRIFT_VERSION} \
  && mkdir -p cmake-build \
  && cd cmake-build \
  && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=0 ${INST} .. \
  && make -j$(nproc) \
  && make install \
  && cd /tmp \
  && wget -O json-${LIB_JSON_VERSION}.tar.gz https://github.com/nlohmann/json/archive/v${LIB_JSON_VERSION}.tar.gz \
  && tar -zxf json-${LIB_JSON_VERSION}.tar.gz \
  && cd json-${LIB_JSON_VERSION} \
  && mkdir -p cmake-build \
  && cd cmake-build \
  && cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=0 ${INST} .. \
  && make -j$(nproc) \
  && make install \
  && cd /tmp \
  && wget -O yaml-cpp-${LIB_YAML_VERSION}.tar.gz https://github.com/jbeder/yaml-cpp/archive/yaml-cpp-${LIB_YAML_VERSION}.tar.gz \
  && tar -zxf yaml-cpp-${LIB_YAML_VERSION}.tar.gz \
  && cd yaml-cpp-yaml-cpp-${LIB_YAML_VERSION} \
  && mkdir -p cmake-build \
  && cd cmake-build \
  && cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="-fPIC" ${INST} -DYAML_CPP_BUILD_TESTS=0 .. \
  && make -j$(nproc) \
  && make install \
  && cd /tmp \
  && wget -O opentracing-cpp-${LIB_OPENTRACING_VERSION}.tar.gz https://github.com/opentracing/opentracing-cpp/archive/v${LIB_OPENTRACING_VERSION}.tar.gz \
  && tar -zxf opentracing-cpp-${LIB_OPENTRACING_VERSION}.tar.gz \
  && cd opentracing-cpp-${LIB_OPENTRACING_VERSION} \
  && mkdir -p cmake-build \
  && cd cmake-build \
  && cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="-fPIC" -DBUILD_TESTING=0 ${INST} .. \
  && make -j$(nproc) \
  && make install \
  && cd /tmp \
  && wget -O jaeger-client-cpp-${LIB_JAEGER_VERSION}.tar.gz https://github.com/jaegertracing/jaeger-client-cpp/archive/v${LIB_JAEGER_VERSION}.tar.gz \
  && tar -zxf jaeger-client-cpp-${LIB_JAEGER_VERSION}.tar.gz \
  && cd jaeger-client-cpp-${LIB_JAEGER_VERSION} \
  && mkdir -p cmake-build \
  && cd cmake-build \
  && cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="-fPIC" -DHUNTER_ENABLED=0 ${INST} -DBUILD_TESTING=0 -DJAEGERTRACING_WITH_YAML_CPP=1 -DJAEGERTRACING_BUILD_EXAMPLES=0 .. \
  && make -j$(nproc) \
  && make install \
  && cd /tmp \
  && wget -O cpp-jwt-${LIB_CPP_JWT_VERSION}.tar.gz https://github.com/arun11299/cpp-jwt/archive/v${LIB_CPP_JWT_VERSION}.tar.gz \
  && tar -zxf cpp-jwt-${LIB_CPP_JWT_VERSION}.tar.gz \
  && cd cpp-jwt-${LIB_CPP_JWT_VERSION} \
  && cp -R include/jwt /users/friedj/install/include \
  && rm -rf /users/friedj/install/include/jwt/json \
  && sed -i 's/\#include \"jwt\/json\/json.hpp\"/\#include \<nlohmann\/json\.hpp\>/g' /users/friedj/install/include/jwt/jwt.hpp \
  && cd /tmp \
  && git clone https://github.com/cpp-redis/cpp_redis.git \
  && cd cpp_redis && git checkout ${LIB_CPP_REDIS_VERSION} \
  && git submodule init && git submodule update \
  && { echo "#include <thread>"; echo "#include <chrono>"; cat sources/core/client.cpp; } > temp && mv temp sources/core/client.cpp \
  && mkdir cmake-build && cd cmake-build \
  && cmake .. -DCMAKE_BUILD_TYPE=Release ${INST} \
  && make -j$(nproc) \
  && make install 

   cd /tmp \
  && git clone https://github.com/CopernicaMarketingSoftware/AMQP-CPP.git \
  && cd AMQP-CPP && git checkout v${LIB_AMQP_CPP_VERSION} \
  && mkdir cmake-build && cd cmake-build \
  && cmake .. -DCMAKE_BUILD_TYPE=Release ${INST} -DAMQP-CPP_BUILD_SHARED=on -DAMQP-CPP_LINUX_TCP=on \
  && make -j$(nproc) && make install \
  && cd /tmp \
  && git clone https://github.com/alanxz/SimpleAmqpClient.git \
  && cd SimpleAmqpClient \
  && git checkout v${LIB_SIMPLEAMQPCLIENT_VERSION} \
  && mkdir cmake-build && cd cmake-build \
  && cmake .. -DCMAKE_BUILD_TYPE=Release $INST \
  && make -j$(nproc) \
  && make install \
  && cd /tmp \
  && git clone https://github.com/redis/hiredis.git \
  && cd hiredis \
  && git checkout v${LIB_HIREDIS_VERSION} \
  && make -j$(nproc) USE_SSL=1 PREFIX=/users/friedj/install \
  && make USE_SSL=1 PREFIX=/users/friedj/install install  \
  && cd /tmp \
  && git clone https://github.com/sewenew/redis-plus-plus.git \
  && cd redis-plus-plus \
  && git checkout ${LIB_REDIS_PLUS_PLUS_VERSION} \
  && sed -i '/Transaction transaction/i\\    ShardsPool* get_shards_pool(){\n        return &_pool;\n    }\n' \
     src/sw/redis++/redis_cluster.h \
  && cmake -DREDIS_PLUS_PLUS_USE_TLS=ON . ${INST} \
  && make -j$(nproc) \
  && make install \
  && pip3 install PyYAML \
  && cd /tmp 



#ENV LD_LIBRARY_PATH /usr/local/lib:${LD_LIBRARY_PATH}
#RUN ldconfig
