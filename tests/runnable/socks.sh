#!/bin/sh
docker run -d --name socks5 -p 9876:1080 serjs/go-socks5-proxy