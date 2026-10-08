# `pktcap` TCP streams — public API header

Header-file-style reference for TCP stream reassembly in the `pktcap`
package: the octets of each direction of a connection, in order, from
dissected frames. It ships inside the package and is self-contained; the top
header is `pktcap/AGENTS.md`. Development documentation lives with the source
at <https://github.com/jose-pr/pktcap>.

This directory (`pktcap/_streams/`) is private and not an import path: every
name below is imported from `pktcap`.

## What it is

A **view over dissected frames**, like the UDP datagram view: the walk, the
registry and `TCPLayer` do not change, and a caller that wants segments still
has them. A reader of a capture is passive: it does not know which copy of an
octet the receiver kept, whether a reset was accepted, or what happened before
the capture began. Every such choice is one of the rules below. The capture is
untrusted, so every amount it controls is bounded.

**`TCPReassembler(*, max_streams=1024, max_buffered=16777216, idle_timeout=300.0)`**
— feed it the `DissectedFrame` objects of a capture in capture order. Not safe
to share between threads. It raises nothing for a frame. `TypeError` for
something that is not a `DissectedFrame` and for an option of the wrong type,
`ValueError` for a limit that is not positive and for an `idle_timeout` too
large for a float.

- **`TCPReassembler.add(frame) -> Tuple[TCPStreamData, ...]`** — one frame; what
  it made deliverable, in the order it became so (a frame can release the
  other direction's held octets before its own). `()` for a frame with no TCP
  over IP.
- **`TCPReassembler.flush() -> Tuple[TCPStreamData, ...]`** — the end of the
  capture: everything still held, each run after a hole with its `missing`,
  connections in order of `stream`. The table is empty afterwards. It sets no
  `end` of its own: a FIN that was captured still ends its direction. An item
  it gives carries the time of the last TCP frame that had a time.
- **`TCPReassembler.stats`** — a `TCPStreamStats` snapshot.

**`TCPStreamData(time, source, destination, data, offset, missing=0, stream=0, end=False)`**
— a named tuple: a run of one direction's octets.

- `time` is the time of the frame that made the octets deliverable.
- `source` and `destination` are `(host, port)` pairs, as in
  `CapturedDatagram`.
- `data` is `bytes`, in order; it is empty only when `end` is true.
- `offset` is the position of `data[0]` in its direction, counted from 0.
  It is a plain integer and never wraps with the sequence number.
- `missing` is how many octets were given up on immediately before `data`.
  They are already counted in `offset`.
- `stream` numbers the connection, both directions alike, from 0 in order of
  first appearance.
- `end` says the direction is over after `data`. It is set on the
  direction's last octets when they reach the end; when octets were given up
  between them and the end, the end is an item of its own, with no `data`
  and those octets in `missing`.

**`TCPStreamStats(segments, streams, delivered, retransmitted, out_of_order, missing, conflicts, ignored, evicted, pending, held, dropped)`**
— a named tuple of counts: TCP segments taken; connections numbered so far;
octets handed out; octets dropped as copies of delivered or held ones;
segments that arrived ahead of a hole; octets given up on; held octets that a
later copy disagreed with; segments and acknowledgments set aside (octets
before the start or beyond a FIN, a reset out of sequence, a segment, FIN or
reset too far ahead (rule 11), a SYN not yet confirmed (rule 9), a SYN-ACK that
contradicts the connection, an acknowledgment beyond everything believed, a
segment in an IP fragment that was not reassembled); connections forgotten at
`max_streams` or for age (a connection every direction of which has ended gives
up its place first and is not counted); connections in the table; octets held
out of order at the moment; octets held when their connection was forgotten.
`retransmitted` also counts octets captured once, after their place was given
up.

**`read_tcp_streams(source, *, reassembler=None, dissector=None, max_frame_size=262144) -> Iterator[TCPStreamData]`**
— `read_dissected` through `TCPReassembler.add`, then `flush()` when the capture
ends: the one-call form, as `read_datagrams` is for UDP.

- `source` is a path or a binary stream, as for `read_frames`.
- `reassembler` is a `TCPReassembler` to use for its options and its `stats`,
  and `dissector` a `FrameDissector` as for `read_dissected`; a new one of each
  by default. A wrong type is a `TypeError` at the call, before anything is
  read.
- Nothing is read before the first item is asked for, and a caller that stops
  early leaves the rest unread.
- Raises `CaptureFormatError` for a damaged container, after every item the
  frames before the damage made deliverable and what was still held.

## The rules

1. **A connection** is the two socket addresses, in either order. Its two
   directions share a `stream` number. VLAN and interface do not tell
   connections apart.
2. **Where a direction starts.** With a SYN captured, offset 0 is the octet
   after it. Without one, offset 0 is the first octet of the first segment
   seen; a segment that turns out to be earlier than that is not delivered.
3. **Sequence numbers wrap** (RFC 9293 section 3.4): positions are compared
   modulo 2**32, a segment less than 2**31 ahead of the next expected octet is
   ahead, anything else is behind.
4. **Octets already delivered are final.** A later copy is a retransmission
   and is dropped unread, whatever it holds: it cannot be compared with what
   was handed out, which is not kept.
5. **Of two copies of an octet not yet delivered, the first captured wins**,
   and a copy that disagrees is counted in `conflicts`. Receivers differ here;
   the capture's own order is the one rule that needs no knowledge of the
   receiver.
6. **A hole is waited for, within bounds.** Octets beyond a hole are held.
   The hole is given up, and what is held is delivered with the number of
   octets missing before it, when: the other side acknowledges past the hole
   (rule 7); a bound is reached (below); the direction or the connection ends;
   or the capture ends (`flush()`).
7. **An acknowledgment from the other side proves receipt.** A segment with
   ACK set is read against the other direction of its connection. When its
   acknowledgment number is ahead of that direction's next expected octet and
   not beyond the furthest octet believed from that sender, every hole before
   it is given up and what is held up to it is delivered, in the frame that
   carried the acknowledgment and before that frame's own octets. One that
   falls inside a hole gives up only the part before it. An acknowledgment
   beyond everything believed from the sender changes nothing and is counted
   in `ignored`: it cannot be told from a forged one, and believing it would
   let one segment make every later octet look like a retransmission. The
   guard holds against a lone forged acknowledgment and, through rule 11,
   against a lone forged segment; two forged segments that agree can still
   move a stream. The acknowledgment of a FIN covers the FIN.
8. **FIN ends a direction** at its position; octets claimed beyond it are
   dropped, those held as well as those of the segment that carries the FIN.
   **RST ends the connection**, both directions, unless its sequence number
   is behind what was already delivered, when it is ignored, or is set aside
   by rule 11. A reset in sequence is taken at its word: held octets come out
   with their `missing`, and the next segments on those addresses start a new
   stream. A reset from a side that has sent nothing has no sequence to
   compare with and is believed whatever its number.
9. **A SYN that is not a retransmission of the connection's own is set
   aside** while the connection has a direction that has not ended: counted
   in `ignored`, it changes nothing, and the connection remembers its sender
   and its number (one per connection; a later SYN replaces it). A segment
   confirms it: one from the other side with ACK set whose acknowledgment
   number is the SYN's plus one, or one from the SYN's sender, other than a
   SYN, that starts from the SYN's number plus one up to 16,777,216 octets
   beyond. When the sender's next segment with octets or a FIN starts
   anywhere else, the SYN was not its own and is forgotten. Once confirmed, the connection it replaces ends, the SYN is not
   counted in `ignored`, the new connection starts on the same addresses
   with that SYN (offset 0 is the octet after it), and the confirming
   segment is read in it. The octets the SYN itself carried are not kept. On
   a connection whose directions have all ended, a new SYN starts the new
   connection at once.
10. **Not done**: the checksum is not verified; the urgent pointer is ignored
    and its octet delivered in place (RFC 6093); a segment inside an IP
    fragment that was not reassembled is ignored.
11. **A segment, a FIN or a reset that starts more than 16,777,216 octets
    beyond the furthest octet believed from its sender is set aside**:
    counted in `ignored`, not held, and the furthest octet believed does not
    move. Nothing a sender transmits in order lands there; a number corrupted
    in a capture usually does. A segment exactly that far is believed. One
    set-aside segment is remembered per direction (where it started and
    ended, no octets). When the next segment from that sender is set aside
    too, and starts at or after where the remembered one started, within
    16,777,216 octets of where it ended, the capture missed what lay between:
    everything the direction holds is delivered, the octets up to the new
    segment are given up and reported in `missing`, the first segment's among
    them, and the direction goes on from the new one; a reset that follows
    on from a remembered segment is believed. A segment believed from the
    sender forgets what was remembered.
12. **A segment is as long as its IP header says**, not as long as the capture
    kept. The octets a snap length cut from its end are those the header
    states beyond the packet captured: for IPv4 the total length, for IPv6 40
    plus the payload length, less the octets captured. A zero length field
    states nothing, octets after the stated length are padding, and a segment
    read from a reassembled datagram is as long as its octets. The stated
    length places a FIN and moves the furthest octet seen, which rule 7 reads.
    A cut segment that arrives in order delivers its captured octets and gives
    up the cut ones at once, so the next item of the direction reports them in
    `missing` (an end item, when a FIN follows); one that arrives out of order
    holds its captured octets and leaves the cut ones a hole like any other.
    Cut octets given up after a direction's last item are in `stats.missing`
    and in no item.

A zero-length segment with no SYN, FIN or RST delivers nothing and starts no
connection, and is still read for its acknowledgment. A SYN takes one sequence
number before its data and a FIN one after it. A SYN-ACK is the answer to the
connection's SYN when its acknowledgment number is the SYN's number plus one,
or up to that plus the octets the SYN carried (TCP Fast Open, RFC 7413
section 4.2); any other acknowledgment contradicts the connection and the
SYN-ACK is ignored.

## Bounds

Every amount a capture controls has a ceiling. Reaching the last three loses
the wait and never the octets; only the first two drop held octets, and
`dropped` counts them. Every octet given up on is reported in the `missing` of
an item, except where its connection was forgotten first, or where it was cut
from the end of a direction's last segment (rule 12): `stats.missing` counts
those too.

| What the capture controls | Ceiling | At the ceiling |
| --- | --- | --- |
| connections tracked | `max_streams` (1,024) | the least recently active is forgotten, its held octets dropped, `evicted` |
| capture time a connection may be silent | `idle_timeout` (300 s) | forgotten when its addresses are next seen, which start a new `stream`; `evicted` |
| octets held out of order over all connections | `max_buffered` (16,777,216), each held piece charged its length plus 64 | the direction that has waited longest gives up its holes and delivers, until the total fits |
| pieces held in one direction, a piece being a run of held octets with no hole in it, joined as segments arrive | 1,024 | that direction gives up its earliest hole |
| one piece too large for `max_buffered` on its own | `max_buffered` | delivered at once behind a given-up hole |

Silence is `abs(time - last)`: a jump either way past the timeout counts, since
a capture controls its clock and a jump back cannot be told from a gap. A time
of exactly `0.0` (a pcapng simple packet block has none), and a time that is
not a number, neither expires a connection nor keeps it alive.

A segment costs a binary search and a walk over the held pieces it covers, at
most 1,024; held octets are joined once, when a run is delivered.

## Not done

- **No stream dissector**: a registered dissector is still given one
  segment's octets, never a stream's, and no command writes streams.
- **No checksum is verified**, and the urgent pointer is ignored.
- **VLAN and interface do not tell connections apart**: the same two socket
  addresses on two VLANs are one connection.

## Example

The streams of a capture, one call:

```python
import pktcap

for item in pktcap.read_tcp_streams("trace.pcap"):
    host, port = item.source
    print(item.stream, "%s:%d" % (host, port), item.offset, item.missing, item.data, item.end)
```

The same with the pieces, to choose the options or to feed frames that do not
come from a file:

```python
reassembler = pktcap.TCPReassembler(max_streams=256, idle_timeout=60.0)
dissector = pktcap.FrameDissector()
chunks = []
for frame in pktcap.read_frames("trace.pcap"):
    chunks.extend(reassembler.add(dissector.dissect(frame)))
chunks.extend(reassembler.flush())
print(b"".join(chunk.data for chunk in chunks if chunk.source[1] == 50000))
print(reassembler.stats.missing)
```
