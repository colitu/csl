# CSL: Colitu Session Layer

A resumable session layer for VPN clients. CSL runs inside the tunnels Colitu
already uses (VLESS-Reality, Trojan, Shadowsocks through Xray / sing-box)
and keeps connections alive when the network changes, a carrier dies, or one
transport gets blocked. Open downloads and calls continue; they do not
reconnect.

Status: **F1 prototype**. The protocol may change until v1.0, and the code
has not been audited. The wire format is in [docs/PROTOCOL.md](docs/PROTOCOL.md).

The implementation and [docs/PROTOCOL.md](docs/PROTOCOL.md) are the current
version 1 interoperability baseline. The earlier design PDF is a proposal;
its framing and timing examples are superseded where they differ.

## Layout

| Path | What it does |
|---|---|
| `frame/` | wire framing, fuzz-tested |
| `handshake/` | HELLO / RESUME with per-carrier nonce and HMAC-SHA256 proof |
| `session/` | resumable byte stream: offsets, ACK, flow control, liveness, linger |
| `mux/` | smux streams over a session, plus the stream request protocol |
| `carrier/` | carrier dialers: `tcp://` and `socks5://` (through Xray / sing-box) |
| `lanes/` | client: carrier race, warm spare, penalties, automatic resume |
| `server/` | server: handshake, session table, replay-safe resume |
| `cmd/csl-server` | node side, listens on loopback behind the cores |
| `cmd/csl-client` | device side for testing, exposes a local SOCKS5 port |
| `cmd/cslbench` | in-process G1 lab, traffic source and verifying downloader |
| `internal/faultnet` | fault-injecting TCP proxy (RST, black hole, 16 KB freeze) |
| `lab/netlab.sh` | Linux namespaces + netem + nftables lab (WSL2 or VPS) |

## Build and test

Go 1.27 or newer.

```bash
go test ./...                       # unit, chaos and G1 lab tests (~20 s)
go test -short ./...                # skips the G1 lab
go build -o bin/ ./cmd/...
bin/cslbench lab -v                 # G1 scenarios with a readable report
```

Run the race detector on Linux or in CI, since it needs cgo: `go test -race ./...`.
On a Linux test host with `iproute2`, `nftables` and Python 3, build the Linux
binaries and run `sudo lab/netlab.sh up`, then `sudo lab/netlab.sh g1`.
The G1 command saves JSON measurements and exits nonzero if verified downloads
fail, a carrier change stalls for over 2 seconds, or median CSL throughput
falls below 90% of the direct baseline on the configured link.
For capacity tests, `csl-server -stats-interval 5s` records the live session,
pending carrier and stream counts, ring storage, and Go heap usage. The server
defaults to `-max-buffer-memory-mib 256` across all sessions. This cap covers
send and receive ring allocations (including resize peaks) and queued
datagram payloads. Full process RSS also includes goroutines, transport
buffers, mux state and the Go runtime; measure it separately when sizing a
node. Results from the two 1 GiB test servers are in the
[test report](docs/LAB-2026-10-06.md).
A [Linux service template](deploy/README.md) applies a 512 MiB cgroup ceiling
to the full CSL server process on a 1 GiB node.

## Try it by hand

```bash
bin/cslbench source -listen 127.0.0.1:9500
bin/csl-server -listen 127.0.0.1:9440 -allow-private -v
bin/csl-client -socks 127.0.0.1:1080 -carrier "tcp://127.0.0.1:9440#A" -carrier "tcp://127.0.0.1:9440#B" -v
bin/cslbench get -socks 127.0.0.1:1080 -target 127.0.0.1:9500 -size 256MiB
```

Through real tunnels, each carrier goes through a local Xray / sing-box
SOCKS inbound to the node's loopback CSL port:

```
-carrier "socks5://127.0.0.1:10808/127.0.0.1:9440?family=tcp#reality"
```

The node's core routing must allow that one loopback destination. Every
other private destination stays blocked by `csl-server` itself.
Set `?family=tcp` or `?family=udp` on each SOCKS5 carrier so the client can
prefer a spare from a different transport family. A Hysteria2/`hy2` label
also implies UDP; unlabeled carriers remain unknown.

## Security notes

- CSL adds no encryption: it relies on the carrier. Never expose
  `csl-server` on a public interface.
- Resume proofs are bound to a fresh server nonce per carrier, so a recorded
  RESUME cannot be replayed.
- `csl-server` refuses loopback, private, link-local and metadata addresses
  unless `-allow-private` is set (lab only).
- `csl-server` refuses non-loopback listener addresses unless
  `-allow-non-loopback` is set for an isolated lab. Pending carrier handshakes
  are bounded by `-max-pending-carriers`.
- `-identity-file` enables node admission with a JSON map from lowercase
  SHA-256 hashes of opaque device credentials to user IDs. The server reloads
  this map every second, and `-max-sessions-per-identity` defaults to 4.
  `-max-streams-per-identity` defaults to 256 across that user's sessions;
  per-session and node-wide stream caps apply as well.
  Clients read their credential from `-credential-file`. Protect the client
  file as a secret. Replace the node's map atomically when access changes:
  removed or reassigned credentials close their active sessions within one
  second. A malformed update rejects new sessions until corrected.
  The node manager should write the file as `{"<64 lowercase hex digits>":
  "<user id>"}` and rename it into place after a complete write. Entries for
  several devices of the same user must map to the same user ID so the shared
  limits apply correctly.
- Logs never contain client addresses or traffic.

## Contributing

CSL is open so that other VPN and censorship-circumvention projects can use,
test and improve it. Issues and pull requests are welcome, especially:

- measurements through real tunnels and on real networks (with the network
  conditions described, never with other people's traffic),
- new fault scenarios for `internal/faultnet` and `lab/netlab.sh`,
- review of `docs/PROTOCOL.md` and the resume/handshake code.

Run `go test ./...` and `go vet ./...` before sending a change; CI also runs
the race detector and a short fuzz pass. Report security problems privately
through GitHub's "Report a vulnerability" button, not in public issues.

## License

CSL is licensed under [Apache-2.0](LICENSE). Its smux dependency is MIT
licensed; see the dependency's license for its terms.
