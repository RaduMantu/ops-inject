$ sudo iptables
    -t filter
    -I OUTPUT
    -p {ip|tcp|udp}
    -d <dst_ip>
    -j NFQUEUE
    --queue-num 0
    --queue-bypass

$ sudo iptables
    -D OUTPUT 1

$ sudo bash -c "./bin/ops-inject -p udp -q 0 -w <(printf '\xcc')"

NOTE: maybe disable checksum offloading?
