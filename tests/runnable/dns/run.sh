#!/bin/sh
docker build -t mock_dns_container .
docker run --rm --mount type=bind,source="$(pwd)"/mock_dns.py,target=/tmp/mock_dns.py -p 127.0.0.1:8853:8853/udp mock_dns_container:latest