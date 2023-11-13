#!/bin/sh

if [ -z "$DIND" ]; then

docker run --rm -it --privileged \
    -v$PWD/target/x86_64-unknown-linux-musl/debug/youki:/youki \
    -v$PWD/dind.sh:/dind.sh \
    -v/tmp/docker.tar:/docker.tar \
    -e DOCKER_HOST="unix:///var/run/docker.sock" \
    -e DIND=1 \
    docker \
    /dind.sh
    "$@"

else

mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<EOF
{
  "features": {
    "containerd-snapshotter": true
  },
  "runtimes": {
    "youki": {
      "path": "/youki"
    }
  }
}
EOF

dockerd 2> /dev/null &
sleep 1
docker run --runtime=youki hello-world

fi
