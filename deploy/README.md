# 1 GiB Linux node service template

`colitu-csl.service` is a deployment template for a dedicated CSL process. It
listens only on loopback, requires the identity file, caps ring/datagram storage
at 256 MiB and applies a 512 MiB cgroup memory ceiling to the whole process.
`MemoryHigh=448M` asks the kernel to reclaim memory earlier. The unit does not
set up Xray/sing-box routing or enable CSL for subscribers.

Provision a non-login `colitu-csl` user and group. Install the CSL binary at
`/usr/local/bin/csl-server`, owned by root. Put a valid identity map at
`/etc/colitu/csl-identities.json`, owned by root and readable by the
`colitu-csl` group only (mode `0640`); its parent directory must be traversable
by that group. Replace the identity map atomically so the server's one-second
reload sees complete JSON. Then install this unit under
`/etc/systemd/system/colitu-csl.service`, run `systemctl daemon-reload`, and
start/enable the unit through the node manager's rollout process.

The 512 MiB limit is for the CSL process. Xray/sing-box and the rest of the
node need their own budget. A cgroup OOM event is a service failure: the
supervisor may restart it up to three times per minute, while clients must
fall back to the existing path. Raise limits only after measuring process RSS
and node available memory under the intended traffic mix.
