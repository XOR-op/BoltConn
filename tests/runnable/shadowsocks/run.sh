#!/bin/sh
docker run --name ssserver-rust \
  -p 8388:8388/tcp \
  -p 8388:8388/udp \
  --mount type=bind,source="$(pwd)"/config.json,target=/etc/shadowsocks-rust/config.json \
  -dit ghcr.io/shadowsocks/ssserver-rust:latest