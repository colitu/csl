# CSL wire protocol, version 1 (F1 interoperability baseline)

This document describes the implemented wire format. The earlier design PDF
is a draft; when its examples differ, this document and the matching code are
the baseline for client/server interoperability. Version 1 may still change
before the public v1.0 release.

CSL (Colitu Session Layer) is a resumable session that runs *inside* an
existing encrypted carrier: VLESS-Reality, Trojan, Shadowsocks, and later
Hysteria2. It adds no cryptography to the data path. It gives the client one
byte stream that survives carrier loss, network changes and blocking of a
single transport.

```
application streams
      │  smux v2 (package mux)
CSL session  ── seq / ACK / resume (package session)
      │  frames (package frame)
carrier: Xray / sing-box tunnel ── TCP / QUIC ── node ── csl-server on loopback
```

## Frames

```
type    uint8
flags   uint8
seq     uvarint
length  uvarint   ≤ 16384
payload [length]
```

| type | name   | seq                          | payload                     |
|-----:|--------|------------------------------|-----------------------------|
| 1    | HELLO  | 0                            | handshake (below)           |
| 2    | RESUME | 0                            | handshake (below)           |
| 3    | DATA   | stream offset of payload[0]  | stream bytes                |
| 4    | ACK    | bytes consumed by receiver   | empty                       |
| 5    | DGRAM  | 0                            | one unreliable datagram     |
| 6    | PING   | ping id                      | empty or pre-request probe  |
| 7    | PONG   | echoed ping id               | empty or echoed probe       |
| 8    | PAD    | 0                            | ignored (traffic shaping)   |
| 9    | CLOSE  | final stream offset          | reason byte (handshake)     |

Flags: `0x01` FlagServer, `0x02` FlagAccept. Receivers ignore unknown types.

## Handshake

The server speaks first on every carrier, with a fresh 32-byte nonce.
Before HELLO or RESUME, the client may send PING frames and the server echoes
their payload in PONG frames. A parked warm spare uses empty PINGs; the initial
carrier selection uses four 16 KiB PINGs to verify 64 KiB of downstream data.
The pre-request payload budget is 64 KiB per carrier.
At most 16 pre-request PINGs are accepted on a carrier.
The pending handshake has an absolute two-minute lifetime; PINGs do not
extend it. Clients normally replace parked spares after one minute.
If an older server rejects the first probe with CLOSE(protocol), the client
redials that carrier and proceeds without probing. Such a carrier is scored
using connect and greeting time, and its parked spare is rotated rather than
pinged.

```
S→C  HELLO  [Server]          ver=1 | nonce(32)

new session:
C→S  HELLO                    ver=1 | window(uvarint) | [credential_len(uvarint) | credential]
S→C  HELLO  [Server|Accept]   id(16) | secret(32) | window(uvarint)

resume:
C→S  RESUME                   ver=1 | id(16) | recvNext(uvarint) | mac(32)
S→C  RESUME [Server|Accept]   recvNext(uvarint)

refusal:  CLOSE  reason(1)    1 version, 2 denied, 3 busy, 4 protocol, 5 expired
```

`mac = HMAC-SHA256(secret, "colitu-csl/1 resume" ‖ nonce ‖ id ‖ uvarint(recvNext))`

The optional HELLO credential is 1–256 opaque bytes. Its length and bytes are
both absent when no credential is configured. An authenticated node requires
it and maps it to a trusted user identity before allocating a session. Older
servers reject this extension, so deploy credential support on nodes before
enabling it in clients. A RESUME uses the session secret and does not resend
the credential. An invalid or missing required credential gets CLOSE(denied);
an authenticated user at the session cap gets CLOSE(busy). Removing a
credential from the node's identity map closes its active sessions.

- The nonce changes per carrier, so a recorded RESUME cannot be replayed.
- Unknown session ids and bad proofs get the same answer (`denied`).
- The secret travels inside the carrier. Server authenticity comes from the
  carrier (Reality / TLS), not from CSL.

## Reliability and flow control

- Every stream byte has an offset. The sender keeps bytes until the peer's
  **application** has consumed them (ACK). That is at most 4 MiB, and `Write`
  blocks when the buffer is full (backpressure).
- A sender may have at most the peer's advertised window (4 MiB) beyond the
  last ACK. The receiver therefore never buffers more than its window, and
  its carrier read loop never blocks.
- Carriers are reliable, so nothing is retransmitted while a carrier lives.
  After a resume the sender continues from the peer's `recvNext`. The
  receiver drops bytes below its own `recvNext`, which makes duplicates
  harmless.
- DATA beyond `recvNext`, an ACK beyond the sent data, or a window overrun
  ends the session with a protocol error.

## Liveness and recovery

- Each side sends PING every 500 ms. Anything received counts as a sign of
  life. A carrier that is silent for 1.5 s is declared dead; the check runs
  every 250 ms.
- The client keeps a warm spare carrier: connected and greeted, parked
  before its request, on a different transport when one exists. The parked
  carrier exchanges PING/PONG every 15 s. When the
  active carrier dies, resume on the spare takes one round trip.
- Without a spare the client races all carriers, starting one every 250 ms,
  and resumes on the first that answers. A failed carrier is penalized for
  5 s, doubling up to 2 min.
- A session without a carrier lingers for 90 s, then both sides drop it.

## Close

`Close()` delivers buffered data, then sends `CLOSE(final offset)`. A peer
that receives CLOSE stops sending, answers with its own CLOSE, and reads
return EOF once buffered data is drained. If the exchange does not finish,
the session ends after 5 s.

## Not in v1 (F1)

Multipath, PAD scheduling, per-network memory, moving sessions between
nodes, a native UDP carrier, DGRAM over SOCKS UDP ASSOCIATE. A local SOCKS5
inbound backed by Hysteria2 may carry CSL's reliable byte stream, but that
path still needs end-to-end validation.
