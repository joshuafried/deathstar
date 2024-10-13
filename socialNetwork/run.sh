#!/bin/bash

set -e
set -x

tmp=$(mktemp -d)

rm -f /tmp/cur
ln -s $tmp /tmp/cur

write_config() {
  local ip="$1"
  local filename="$2"

  cat <<EOF > "$filename"
host_addr $ip
host_netmask 255.255.0.0
host_gateway 172.32.0.1
runtime_kthreads 1
runtime_spinning_kthreads 0
runtime_guaranteed_kthreads 0
runtime_priority lc
runtime_quantum_us 0
EOF
}

# docker compose up user-mongodb > $tmp/user-mongo.log 2>&1 &
# docker compose up home-timeline-redis > $tmp/home-timeline-redis.log 2>&1 &
# docker compose up jaeger-agent > $tmp/jaeger-agent.log 2>&1 &
# docker compose up social-graph-mongodb > $tmp/social-graph-mongodb.log 2>&1 &
# docker compose up social-graph-redis > $tmp/social-graph-redis.log 2>&1 &

# sleep 1

function cleanup {
  sudo pkill junc
}
trap cleanup SIGINT SIGTERM EXIT

start_service() {
  local sname="$1"
  local ip="$2"

  write_config $ip ${tmp}/${sname}.config
  ~/junction/build/junction/junction_run ${tmp}/${sname}.config --ld_path $LD_LIBRARY_PATH -- /users/friedj/install/${sname} > ${tmp}/${sname}.log 2>&1 &
}

# start_service PostStorageService 172.32.0.8
# start_service HomeTimelineService 172.32.0.23
# start_service UserTimelineService 172.32.0.22
# start_service UserService 172.32.0.17
# start_service SocialGraphService 172.32.0.5
# start_service ComposePostService 172.32.0.16
# start_service UniqueIdService 172.32.0.2
# start_service MediaService 172.32.0.3
# start_service TextService 172.32.0.13
# start_service UrlShortenService 172.32.0.25
# start_service UserMentionService 172.32.0.20

# write_config 172.32.0.8 $tmp/post-storage-service.config
# ~/junction/build/junction/junction_run $tmp/post-storage-service.config --ld_path $LD_LIBRARY_PATH -- /users/friedj/install/PostStorageService > $tmp/post-storage-service.log 2>&1 &

# write_config 172.32.0.23 $tmp/home-timeline-service.config
# ~/junction/build/junction/junction_run $tmp/home-timeline-service.config --ld_path $LD_LIBRARY_PATH -- /users/friedj/install/HomeTimelineService > $tmp/home-timeline-service.log 2>&1 &

# write_config 172.32.0.16 $tmp/compose-post-service.config
# ~/junction/build/junction/junction_run $tmp/compose-post-service.config --ld_path $LD_LIBRARY_PATH -- /users/friedj/install/ComposePostService > $tmp/compose-post-service.log 2>&1 &

# write_config 172.32.0.12 $tmp/post-storage-service.config
# ~/junction/build/junction/junction_run $tmp/post-storage-service.config --ld_path $LD_LIBRARY_PATH -- /users/friedj/install/PostStorageService > $tmp/post-storage-service.log 2>&1 &

docker compose up
