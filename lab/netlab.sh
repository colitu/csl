#!/usr/bin/env bash
# CSL network lab for Linux (WSL2 Ubuntu or a throwaway VPS).
#
# Builds three network namespaces and runs the real binaries across a
# "censor" box in the middle, where tc netem adds latency/loss and nftables
# injects the faults:
#
#   csl-cli 10.77.1.2  <->  csl-mid 10.77.1.1 | 10.77.2.1  <->  csl-srv 10.77.2.2
#   csl-client                (netem, nftables)               csl-server :9440 (lane A)
#   cslbench get                                                         :9441 (lane B)
#                                                              cslbench source :9500
#
# Requires root, iproute2, nftables and python3. Binaries are expected in ../bin/linux:
#   GOOS=linux GOARCH=amd64 go build -o bin/linux/ ./cmd/...
#
# Usage:
#   sudo lab/netlab.sh up                 create namespaces, start server + source + client
#   sudo lab/netlab.sh netem 25ms 0.5% 100mbit
#                                         per-direction delay (RTT = 2x), loss, rate
#   sudo lab/netlab.sh reset 9440         reset (RST) live connections on a lane port
#   sudo lab/netlab.sh blackhole 9440     silently drop a lane port
#   sudo lab/netlab.sh freeze 9440 16384  freeze connections after N downstream bytes
#   sudo lab/netlab.sh clear              remove all faults and netem
#   sudo lab/netlab.sh get [size] [rate]  download through CSL
#   sudo lab/netlab.sh direct [size]      download without CSL (baseline)
#   sudo lab/netlab.sh g1                 run and check G1, write lab/results/
#   sudo lab/netlab.sh down               stop everything and delete namespaces
#
# Runs on an isolated Linux host with the required network tools installed.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${CSL_BIN:-$HERE/../bin/linux}"
RUN="/run/csl-lab"
CLI=csl-cli MID=csl-mid SRV=csl-srv
SRV_IP=10.77.2.2
PORT_A=9440 PORT_B=9441 SRC_PORT=9500 SOCKS=127.0.0.1:1080

nsx() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

up() {
    [[ -x "$BIN/csl-server" ]] || { echo "missing $BIN/csl-server (see header)"; exit 1; }
    if [[ ! -e /proc/sys/net/netfilter/nf_conntrack_acct ]]; then
        modprobe nf_conntrack
    fi
    mkdir -p "$RUN"
    for ns in $CLI $MID $SRV; do ip netns add $ns; nsx $ns ip link set lo up; done
    ip link add cli0 type veth peer name mid-cli
    ip link add srv0 type veth peer name mid-srv
    ip link set cli0 netns $CLI;    ip link set mid-cli netns $MID
    ip link set srv0 netns $SRV;    ip link set mid-srv netns $MID
    nsx $CLI ip addr add 10.77.1.2/24 dev cli0
    nsx $MID ip addr add 10.77.1.1/24 dev mid-cli
    nsx $MID ip addr add 10.77.2.1/24 dev mid-srv
    nsx $SRV ip addr add $SRV_IP/24 dev srv0
    nsx $CLI ip link set cli0 up; nsx $MID ip link set mid-cli up
    nsx $MID ip link set mid-srv up; nsx $SRV ip link set srv0 up
    nsx $CLI ip route add default via 10.77.1.1
    nsx $SRV ip route add default via 10.77.2.1
    nsx $MID sysctl -qw net.ipv4.ip_forward=1
    nsx $MID nft add table inet csl
    nsx $MID nft add chain inet csl csl_forward '{ type filter hook forward priority 0; policy accept; }'
    nsx $MID sysctl -qw net.netfilter.nf_conntrack_acct=1

    # In the lab the server must reach the source on a private address.
    nsx $SRV "$BIN/cslbench" source -listen $SRV_IP:$SRC_PORT >"$RUN/source.log" 2>&1 &
    echo $! >"$RUN/source.pid"
    nsx $SRV "$BIN/csl-server" -listen $SRV_IP:$PORT_A,$SRV_IP:$PORT_B -allow-non-loopback -allow-private -stats-interval 5s -v >"$RUN/server.log" 2>&1 &
    echo $! >"$RUN/server.pid"
    sleep 0.5
    start_client
    echo "lab up; logs in $RUN"
}

start_client() {
    nsx $CLI "$BIN/csl-client" -socks $SOCKS -v \
        -carrier "tcp://$SRV_IP:$PORT_A#A" -carrier "tcp://$SRV_IP:$PORT_B#B" >"$RUN/client.log" 2>&1 &
    echo $! >"$RUN/client.pid"
    for _ in {1..100}; do
        if nsx $CLI ss -H -ltn | grep -Fq "$SOCKS"; then return 0; fi
        sleep 0.1
    done
    echo "CSL client did not start listening; see $RUN/client.log" >&2
    return 1
}

restart_client() {
    local pid
    for pid in $(ip netns pids "$CLI"); do
        if [[ "$(cat "/proc/$pid/comm" 2>/dev/null)" == csl-client ]]; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    for _ in {1..30}; do
        if ! nsx $CLI ss -H -ltn | grep -Fq "$SOCKS"; then break; fi
        sleep 0.1
    done
    start_client
}

down() {
    # Killing the ip-netns-exec wrapper alone leaves its child process and
    # network namespace alive. Stop every process still inside our namespaces.
    for ns in $CLI $MID $SRV; do
        while read -r pid; do
            [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
        done < <(ip netns pids "$ns" 2>/dev/null || true)
    done
    sleep 0.2
    for ns in $CLI $MID $SRV; do ip netns del "$ns" 2>/dev/null || true; done
    echo "lab down"
}

netem() {
    local delay=${1:-25ms} loss=${2:-0%} rate=${3:-}
    for dev in mid-cli mid-srv; do
        nsx $MID tc qdisc replace dev $dev root netem delay "$delay" loss "$loss" ${rate:+rate $rate}
    done
}

clear_faults() {
    nsx $MID nft flush chain inet csl csl_forward
    for dev in mid-cli mid-srv; do nsx $MID tc qdisc del dev $dev root 2>/dev/null || true; done
}

reset_lane() {
    local port=$1 h
    h=$(nsx $MID nft --echo --handle add rule inet csl csl_forward tcp sport "$port" reject with tcp reset |
        sed -n 's/.*# handle \([0-9]*\).*/\1/p')
    sleep 0.3
    nsx $MID nft delete rule inet csl csl_forward handle "$h"
}

blackhole() {
    nsx $MID nft add rule inet csl csl_forward tcp dport "$1" drop
    nsx $MID nft add rule inet csl csl_forward tcp sport "$1" drop
}

# Conntrack counts the server's packets as the reply direction.
freeze() {
    local port=$1 bytes=${2:-16384}
    nsx $MID nft add rule inet csl csl_forward tcp sport "$port" ct reply bytes gt "$bytes" drop
    nsx $MID nft add rule inet csl csl_forward tcp dport "$port" ct reply bytes gt "$bytes" drop
}

get() {
    nsx $CLI "$BIN/cslbench" get -socks $SOCKS -target $SRV_IP:$SRC_PORT -size "${1:-64MiB}" -rate "${2:-0}" -json
}

direct() {
    nsx $CLI "$BIN/cslbench" get -direct -target $SRV_IP:$SRC_PORT -size "${1:-64MiB}" -json
}

active_port() {
    local lane
    lane=$(sed -n 's/.*carrier \([AB]\): attached.*/\1/p' "$RUN/client.log" | tail -n 1)
    case "$lane" in
        A) echo "$PORT_A" ;;
        B) echo "$PORT_B" ;;
        *) echo "no active lane in $RUN/client.log" >&2; return 1 ;;
    esac
}

# g1 runs each scenario under a realistic link and records the results.
g1() {
    local out n fault size=${CSL_G1_SIZE:-64MiB}
    out="$HERE/results/g1-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$out"
    clear_faults; netem 25ms 0.5% 100mbit
    for n in 1 2 3; do
        direct "$size" >"$out/direct-$n.json" || true
        get "$size" >"$out/csl-$n.json" || true
    done
    clear_faults; netem 25ms 0%
    restart_client
    (sleep 2; reset_lane "$(active_port)") & fault=$!
    get 48MiB 8MiB >"$out/reset.json" || true
    wait "$fault"
    restart_client
    (sleep 2; blackhole "$(active_port)") & fault=$!
    get 48MiB 8MiB >"$out/blackhole.json" || true
    wait "$fault"
    clear_faults; netem 25ms 0%
    # Freeze a fresh lane before selection. The 64 KiB probe must reject it.
    freeze $PORT_A 16384
    restart_client
    get 48MiB 8MiB >"$out/freeze.json" || true
    clear_faults
    echo "results: $out"
    python3 "$HERE/check_g1.py" "$out"
}

case "${1:-}" in
    up) up ;;
    down) down ;;
    netem) shift; netem "$@" ;;
    clear) clear_faults ;;
    reset) reset_lane "$2" ;;
    blackhole) blackhole "$2" ;;
    freeze) freeze "$2" "${3:-16384}" ;;
    get) shift; get "$@" ;;
    direct) shift; direct "$@" ;;
    g1) g1 ;;
    *) sed -n '2,32p' "$0"; exit 2 ;;
esac
