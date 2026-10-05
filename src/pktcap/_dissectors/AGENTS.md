# `pktcap` dissectors — public API header

Header-file-style reference for dissection in the `pktcap` package: the
contract a dissector keeps, the registry dissectors are found in, how to write
and check one, and what each built-in dissector reads and leaves alone. It
ships inside the package and is self-contained; the top header is
`pktcap/AGENTS.md`. Development documentation lives with the source at
<https://github.com/jose-pr/pktcap>.

This directory (`pktcap/_dissectors/`) is private and not an import path:
every name below is imported from `pktcap`.

## The contract

A **dissector** reads one layer. It is any callable of this shape
(`Dissector` is the alias `Callable[[bytes], Dissected]`):

```python
def dissect(data: bytes) -> pktcap.Dissected: ...
```

`data` is the octets of the layer and of everything after it, exactly as the
capture or the layer before left them: cut short, lying about their lengths,
or not this protocol at all.

**`Dissected(layer, payload, next=(), fragment=None)`** — a named tuple: what
a dissector returns.

| Field | Is |
| --- | --- |
| `layer` | the record of what was read: any object, added to the frame's `layers`. `None` adds no layer (raw IP has no header of its own) |
| `payload` | `bytes`: the octets that follow the layer, never longer than `data`. Padding the layer knows about is left out |
| `next` | selectors for what `payload` starts with, tried in order: the first one with a registered dissector continues the walk. Empty, or none registered, ends it, and `payload` is what the frame has left |
| `fragment` | a `Fragment` when `payload` is one piece of a larger unit, else `None` |

A **selector** (`Selector`, the alias `Tuple[str, int]`) is a kind and a
number. The built-in dissectors name these kinds: `("linktype", n)` for a
capture's `LINKTYPE_` number, `("ethertype", n)`, `("ip", n)` for an IP
protocol number, and `("udp", port)` and `("tcp", port)`, the destination
port tried before the source. A kind is just a name: a dissector may name
`("myproto.type", 3)` and whoever registered under it is found.

**`Fragment(key, offset, last)`** — a named tuple: where a piece belongs.
`key` is any hashable value shared by the pieces of one unit, `offset` where
this piece starts in the unit, in octets, `last` whether it is the final
piece. The frame dissector adds the `source` and `destination` of the nearest
layer that has them to the key, holds the pieces, and continues the walk with
the whole unit from the frame that completes it. The limits are the
reassembly ceilings of the top header (65,535 octets and 1,024 pieces per
unit, 256 units at once, 30 seconds).

What a dissector must do, and what happens when it does not:

- **Check every length before using it.** `data` may be empty.
- **Raise `ValueError` for octets that are not the layer**: too short, a
  length that points past the end, a version that is not this protocol.
  `DissectError` is the subclass the built-in ones raise. The frame keeps the
  layers before, gets the `error` text `"<kind> <number>: <message>"`, and is
  counted `malformed`. Keep the message free of the octets themselves.
- **Anything else it raises is a defect in it**, and is contained: the frame
  comes back with that layer undissected, is counted `failed`, and the
  failure is logged once per selector. An `IndexError` or `struct.error` from
  an unchecked length lands here.
- Return a `Dissected` whose `payload` is `bytes`; anything else counts as
  `failed` too.
- **Be a function of `data` alone**: no input or output, no waiting, work
  bounded by `len(data)`. One registry serves every frame dissector that uses
  it, so state kept between calls is shared between captures. A protocol that
  needs state across frames (a transfer that moves to other ports) keeps it
  in the caller, over the datagram view.

A layer record is best a `typing.NamedTuple` of plain values named
`<Protocol>Layer`: immutable and hashable, `frame.layer(TFTPLayer)` finds it,
`frame_record` writes its fields, and the filter key `proto=tftp` matches it.

## The registry

**`DissectorRegistry(*, builtins=True)`** — the dissectors one
`FrameDissector` chooses from. Two registries share nothing.
`builtins=False` starts empty: nothing is dissected that the caller did not
choose.

- **`DissectorRegistry.register(kind, value, dissector, *, replace=False) -> None`**
  — make `dissector` the one for the selector `(kind, value)`. **A selector
  that is taken is a `ValueError`** unless `replace=True`: two libraries
  claiming one port find out when they register, not when a capture decodes
  as the wrong protocol. A built-in is replaced the same way. `TypeError` for
  a kind that is not a non-empty `str`, a value that is not an `int`, or a
  dissector that cannot be called.
- **`DissectorRegistry.unregister(kind, value) -> None`** — forget it; what it
  selected comes back undissected. `ValueError` when there is none.
- **`DissectorRegistry.get(kind, value) -> Optional[Dissector]`** — the
  dissector, or `None`: a selector with no dissector is the ordinary end of a
  walk, not an error.
- **`DissectorRegistry.selectors() -> Tuple[Selector, ...]`** — every selector
  with a dissector, sorted.
- **`DissectorRegistry.copy() -> DissectorRegistry`** — the same dissectors in
  a registry that then changes on its own.

**`default_registry() -> DissectorRegistry`** — the one registry a
`FrameDissector` uses when given none. One object for the process.

**`register_dissector(kind, value, dissector, *, replace=False) -> None`** —
`default_registry().register(...)`: the one line a protocol library's user
calls to have every capture read in the process dissect that protocol.

**Entry points are not read.** Installing a package registers nothing: a
capture dissects the same whatever else is installed, and a dissector is in a
registry because code the caller ran put it there. A protocol library offers a
function that registers, or the dissector itself; it does not register on
import.

## Writing and checking a dissector

```python
import struct
from typing import NamedTuple

import pktcap


class TFTPLayer(NamedTuple):
    opcode: int
    filename: str


def dissect_tftp(data: bytes) -> pktcap.Dissected:
    if len(data) < 4:
        raise pktcap.DissectError("a TFTP packet is at least 4 octets")
    (opcode,) = struct.unpack_from("!H", data)
    name, _, rest = data[2:].partition(b"\0")
    return pktcap.Dissected(TFTPLayer(opcode, name.decode("ascii", "replace")), rest)


registry = pktcap.DissectorRegistry()
registry.register("udp", 69, dissect_tftp)
dissector = pktcap.FrameDissector(registry)
for frame in pktcap.read_dissected("trace.pcap", dissector=dissector):
    request = frame.layer(TFTPLayer)
    if request is not None:
        print(frame.datagram().source, request.opcode, request.filename)
```

**`check_dissector(dissector, samples, *, rounds=2000, seed=0) -> None`** —
assert that a dissector keeps the contract whatever it is given: the check the
built-in dissectors pass, for a protocol library's own tests. Each of
`samples` (well-formed inputs, as `bytes`) is tried as it is and then
`rounds` times damaged, octets changed and the tail cut off, the same way for
the same `seed`. For every input the dissector must return a `Dissected`
whose payload is `bytes` not longer than the input, whose `next` is selectors
and whose `fragment` is a `Fragment` or `None`, or raise `ValueError`.
`AssertionError` names the first input that broke it, as hex. `ValueError`
when no sample is given.

```python
def test_the_tftp_dissector_keeps_the_contract():
    pktcap.check_dissector(dissect_tftp, [b"\x00\x01boot.efi\x00octet\x00"])
```

## The built-in dissectors

| Selector | Reads | Layer | Names next |
| --- | --- | --- | --- |
| `linktype 1` | an Ethernet II header, 14 octets | `EthernetLayer` | `ethertype`, when the field is 1,536 or more |
| `ethertype 0x8100`, `0x88A8`, `0x9100` | one VLAN tag, 4 octets | `VLANLayer` | `ethertype`, by the same rule |
| `linktype 113` | a Linux cooked header v1, 16 octets | `LinuxCookedLayer` | `ethertype` |
| `linktype 276` | a Linux cooked header v2, 20 octets | `LinuxCookedLayer` | `ethertype` |
| `linktype 0` | a BSD loopback header: the address family in the byte order of the capturing host, either one | `LoopbackLayer` | `ethertype 0x0800` for family 2, `0x86DD` for 10, 24, 28 or 30 |
| `linktype 108` | an OpenBSD loopback header: the family in network order | `LoopbackLayer` | the same |
| `linktype 12`, `14`, `101`, `228`, `229` | nothing: raw IP has no link header | none | `ethertype 0x0800` or `0x86DD`, by the version in the first octet |
| `ethertype 0x0800` | an IPv4 header, its options skipped | `IPv4Layer` | `ip <protocol>` |
| `ethertype 0x86DD` | an IPv6 fixed header, 40 octets | `IPv6Layer` | `ip <next header>` |
| `ip 0`, `43`, `60` | one hop-by-hop, routing or destination-options header | `IPv6ExtensionLayer` | `ip <next header>` |
| `ip 44` | an IPv6 fragment header, 8 octets | `IPv6FragmentLayer` | `ip <next header>` |
| `ip 17` | a UDP header, 8 octets | `UDPLayer` | `udp <destination port>`, then `udp <source port>` |
| `ip 6` | a TCP header and its options | `TCPLayer` | `tcp <destination port>`, then `tcp <source port>` |

What they leave alone:

- **No checksum is verified**, IPv4, UDP or TCP: a capture taken on the
  sending host shows checksums the network card had yet to fill in.
- **IPv4 options, IPv6 extension-header contents and TCP options are not
  decoded.** The IPv4 ones are skipped; the other two are kept as octets
  (`IPv6ExtensionLayer.data`, `TCPLayer.options`).
- **TCP streams are not reassembled**: a segment's payload is what follows
  its header, in the order the frames were captured, retransmissions
  included.
- **An 802.3 frame** (the type field is a length, under 1,536) ends at
  `EthernetLayer`: LLC and SNAP are not read.
- **Octets past the length an IP header states** are link-layer padding and
  are dropped from the payload, as is an Ethernet frame check sequence that
  was captured with a frame.
- **A zero length field** (IPv4 total, IPv6 payload, UDP) means "all that is
  left": a network card that segments the send leaves it unset.
- Nothing is built in for ARP, ICMP, ICMPv6, IPsec, GRE, SCTP, MPLS, PPPoE,
  802.11 or any application protocol. Each is a selector with no dissector:
  the frame ends there with the rest as its payload, until one is registered
  (`("ethertype", 0x0806)` for ARP, `("ip", 1)` for ICMP).

## The layer records

Each is a named tuple of plain values. An address is text, a flag a `bool`,
octets `bytes`.

**`EthernetLayer(destination, source, ethertype)`** — the MAC addresses as
`aa:bb:cc:dd:ee:ff`, and the type field.

**`VLANLayer(id, priority, drop_eligible, ethertype)`** — one 802.1Q or
802.1ad tag: the VLAN identifier (0 to 4095), the priority code point (0 to
7), the drop-eligible bit, and the type of what follows. A QinQ frame has two
in a row, the outer first.

**`LinuxCookedLayer(packet_type, hardware_type, address, ethertype, interface=None)`**
— what Linux records for its `any` device. `packet_type` is 0 to this host, 1
broadcast, 2 multicast, 3 to another host, 4 sent by this host;
`hardware_type` the `ARPHRD_` number of the device (1 Ethernet, 772
loopback); `address` the sender's link-layer address as hex text, at most
eight octets; `interface` the interface index, `None` in version 1.

**`LoopbackLayer(family)`** — the address family as the capturing host
numbered it.

**`IPv4Layer(source, destination, protocol, ttl, identification, dont_fragment, more_fragments, fragment_offset, length)`**
— `fragment_offset` is in octets; `length` is the total length the header
states. `IPv4Layer.is_fragment` is true for a piece of a fragmented datagram.

**`IPv6Layer(source, destination, next_header, hop_limit, payload_length, traffic_class, flow_label)`**
— a v4-mapped address is written `::ffff:10.0.0.5` on every Python.

**`IPv6ExtensionLayer(next_header, data)`** — `data` is the header's octets
after its first two.

**`IPv6FragmentLayer(next_header, fragment_offset, more_fragments, identification)`**
— `fragment_offset` is in octets. `IPv6FragmentLayer.is_fragment` is false for
an "atomic" fragment, a whole datagram in one piece, which is not held.

**`UDPLayer(source_port, destination_port, length, checksum)`** — `length` is
what the header states, header included; more than the octets that follow
means the capture cut the datagram short.

**`TCPLayer(source_port, destination_port, sequence, acknowledgment, flags, window, checksum, urgent, options)`**
— `sequence` and `acknowledgment` are as on the wire, `window` unscaled.
`flags` is the nine flag bits: `0x01` FIN, `0x02` SYN, `0x04` RST, `0x08`
PSH, `0x10` ACK, `0x20` URG, `0x40` ECE, `0x80` CWR, `0x100` AE.
`TCPLayer.syn`, `.ack`, `.fin` and `.rst` read four of them.

## Ceilings

Each built-in dissector reads one header and checks every length it states
against the octets present, so its work is bounded by the frame. What no
single dissector can bound is the frame dissector's:

| What a frame states | Ceiling | At the ceiling |
| --- | --- | --- |
| dissectors run on one frame: a stack of tags, a chain of extension headers, a registered dissector that names itself | 32 | the walk stops, the frame is `malformed` |
| the sender address length in a Linux cooked header | 8 octets, the width of the field | the rest is not read |
| pieces, octets, units and age of a fragmented unit | the reassembly ceilings of the top header | the unit is discarded and counted `dropped` |
