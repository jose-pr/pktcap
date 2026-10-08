# `pktcap` capture sources — public API header

Header-file-style reference for where `pktcap` takes frames from live: an
interface (`LiveCapture`, Linux, privileged) and UDP sockets the caller bound
(`UDPCapture`, every platform, no privilege), with `datagram_frame`, the frame a
datagram from a socket becomes. It ships inside the package and is
self-contained; the top header is `pktcap/AGENTS.md`. Development
documentation lives with the source at <https://github.com/jose-pr/pktcap>.

This directory (`pktcap/_sources/`) is private and not an import path: every
name below is imported from `pktcap`.

## Capturing live

**Linux only**, through an `AF_PACKET` socket, and the process needs the
`CAP_NET_RAW` capability (root, or `setcap cap_net_raw+ep` on the
interpreter). Everywhere else, and wherever a capture tool is preferred, pipe
one in: `tcpdump -i eth0 -U -w - | your-program` and
`read_dissected(sys.stdin.buffer)`; or read UDP from sockets, below. Capturing
never sends anything.

**`has_live_capture() -> bool`** — whether this platform has `AF_PACKET`. It
says nothing about permission.

**`LiveCapture(interface=None, *, timeout=1.0)`** — every packet on one
interface, or on all of them when `interface` is `None`. A context manager;
constructing one opens nothing.

- `interface` is `netimps.InterfaceLike`: a name, a `netimps.Interface`, or
  anything `netimps.get_interface` finds one by (an address, a MAC).
- **`LiveCapture.open() -> None`** — open the socket; `with` does it. Does
  nothing when already open. `LiveCaptureError` where the platform has no
  `AF_PACKET` (before any interface is looked up), the kernel's `PermissionError` without the capability,
  `ValueError` when no interface matches.
- **`LiveCapture.read() -> Optional[CapturedFrame]`** — the next packet, IP or
  not, or `None` when `timeout` seconds pass without one. A frame has link
  type 276 (Linux cooked capture v2, what tcpdump writes for its `any`
  device), the time it was read and the interface's index: ready for a
  `FrameDissector`, and for a writer, whose file other tools then read.
- Iterating a capture yields frames until it is closed.
- **`LiveCapture.fileno() -> int`** — the socket's descriptor, for a caller's
  own selector or event loop. There is no asynchronous twin.
- **`LiveCapture.close() -> None`** — final, complete on return, harmless
  twice.
- On a loopback device every packet is seen leaving and arriving; only the
  arriving copy is returned. Loopback is told by the device type the kernel
  reports, not by the name `lo`.

**`sniff_frames(interface=None, *, stop=None, dissector=None) -> Iterator[DissectedFrame]`**
— `LiveCapture` and a `FrameDissector` in one call, what `read_dissected` is
for a file: every frame as it arrives, dissected, whatever it carries. The
socket is opened when the first frame is asked for (which is when
`LiveCaptureError` or `PermissionError` is raised) and closed when the
iterator ends or is closed. `stop()` is called between packets, and at least
once a second on a quiet interface; returning true ends the iteration.
`TypeError` at the call for a `stop` that is not callable or a `dissector`
that is not a `FrameDissector`.

**`sniff(interface=None, *, stop=None, dissector=None) -> Iterator[CapturedDatagram]`**
— `sniff_frames` through the datagram view: UDP datagrams as they arrive, the
rest passed over. The same opening, closing, `stop` and errors.

## Capturing from UDP sockets

Binding a port and recording what arrives needs no privilege and works where
live capture does not. The caller binds the sockets (`netimps.bind` and
`netimps.UDPEndpoint`); this library reads them.

**What it sees:** datagrams delivered to the ports bound, on this host. **What
it does not:** other hosts' unicast traffic, anything this host sends, the link
layer, the real IP header, and IP fragments, which the kernel has put together
already. **The IP header of every frame is made up** (`datagram_frame`): TTL 64,
no fragmentation, valid checksums; do not read a TTL, an identification or a
type of service from it.

**It holds the port.** A server already bound to it makes the bind fail; with
address reuse (`netimps.bind` allows it by default) the two sockets can share
or take each other's datagrams. Bind without it
(`netimps.bind(host, port, reuse_address=False)`), and to watch a port a server
holds, capture on the interface instead.

**`datagram_frame(datagram, *, interface=None, ident=0) -> CapturedFrame`** —
a `CapturedDatagram` as the raw-IP frame (link type 101) a dissector reads,
with the octets `PcapWriter` writes for it. `interface` is the arrival
interface's number or `None`; `ident` the IPv4 identification, kept to 16
bits. A v4-mapped pair of addresses is an IPv4 packet, one IPv4 end with one
IPv6 end an IPv6 packet with the IPv4 end mapped, and a zone is not on the
wire. **The law:** `FrameDissector().dissect(datagram_frame(d)).datagram() == d`
for a datagram whose hosts are written as they appear on the wire (a mapped
pair comes back as plain IPv4 hosts, a zone comes back removed). `ValueError`
for a host that is no address (a name is not looked up), a port outside
0-65535, a payload over 65,507 octets (IPv4) or 65,527 (IPv6), a time out of
range or an `interface` outside 0 to 2**32 - 1; `TypeError` for a wrong type;
nothing is built then.

**`UDPCapture(endpoints, *, timeout=1.0, max_size=65535)`** — the twin of
`LiveCapture`, every platform. A context manager and an iterator of frames.

- `endpoints` is an iterable of at most **256** bound `netimps.UDPEndpoint`
  objects. **The capture owns them from construction** and closes them in
  `close()`. A call that raises leaves them the caller's.
- `timeout` is how long `read()` waits (positive); `max_size` the largest
  payload returned, 1 to 65,535. `ValueError` for no endpoint, more than 256, a
  `timeout` not above zero or a `max_size` outside range; `TypeError` for an
  item that is no `UDPEndpoint` or an option of the wrong type.
- **`UDPCapture.read() -> Optional[CapturedFrame]`** — the next datagram as a
  frame, or `None` when `timeout` seconds pass without one. The frame has link
  type 101, the time it was read, the arrival interface's index when the host
  reports one (else `None`), the sender as the source, and as the destination
  the address the datagram was sent to when the host says so, **else the
  address the socket is bound to, which may be a wildcard (`0.0.0.0`, `::`)**
  and is not guessed. Endpoints are served in turn, so a busy one does not
  starve another. `ValueError` when closed; `OSError` when a socket fails.
- **`UDPCapture.truncated`** — how many datagrams were read and dropped
  because they held more than `max_size` octets: a socket returns only the
  start of such a datagram, so it is counted and not returned. One read asks
  for `max_size + 1` octets and the count is by length.
- **`UDPCapture.aread() -> Optional[CapturedFrame]`** — `read()` awaited: one
  task for each endpoint, started by the first call, feeds one queue of 64
  frames; a slow consumer stops the tasks and the kernel drops what its buffer
  cannot hold. Use one event loop for a capture's life; do not mix with `read()`.
  `asyncio` is imported by the first call and not before.
- **`UDPCapture.close() -> None`** — closes every endpoint; final, complete on
  return, harmless twice. **`UDPCapture.aclose() -> None`** — the same awaited:
  every reader task has been cancelled and has left. From a coroutine use this,
  since `close()` waits for netimps' reader thread without letting the loop run.

**`sniff_udp(endpoints, *, stop=None, dissector=None) -> Iterator[DissectedFrame]`**
— `UDPCapture` and a `FrameDissector` in one call, as `sniff_frames` is for an
interface. The endpoints are the iterator's from the call; it closes them when
it ends, fails, is closed (`close()` on the iterator, also before the first
frame) or is dropped. `stop()` is called between datagrams and at least once a
second on a quiet socket; true ends the iteration. `TypeError` at the call for
a `stop` that is not callable, a `dissector` that is not a `FrameDissector`, or
an item that is no `UDPEndpoint`; `ValueError` for none or more than 256.

**`asniff_udp(endpoints, *, dissector=None) -> AsyncIterator[DissectedFrame]`**
— `sniff_udp` for an event loop, on `UDPEndpoint.arecv`. When it ends, fails or
is cancelled, every task is cancelled and every socket closed; a loop that
stops early awaits the iterator's `aclose()`. It has no `stop`: break and
`aclose()`, or cancel.

Ceilings:

| What is chosen | Ceiling | At the ceiling |
| --- | --- | --- |
| endpoints one capture reads | 256 | `ValueError` before any is looked at |
| octets of a payload | `max_size` (65,535 at most) | the datagram is counted in `truncated` and not returned |
| frames queued in `aread` | 64, and one datagram in each reader's hand | the readers wait; the kernel drops the rest |
