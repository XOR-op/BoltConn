docker run \
    --name trojan-go \
    -d \
    -v ./:/etc/trojan-go/ \
    --network host \
    p4gefau1t/trojan-go
    /etc/trojan-go/server.yaml