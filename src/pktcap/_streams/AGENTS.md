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
`ValueError` for a limit that is not positive.

- **`TCPReassembler.add(frame) -> Tuple[TCPStreamData, ...]`** — one frame; what
  it made deliverable, in the order it became so (a frame can release the
  other direction's held octets before its own). `()` for a frame with no TCP
  over IP.
- **`TCPReassembler.flush() -> Tuple[TCPStreamData, ...]`** — the end of the
  capture: everything still held, each run after a hole with its `missing`,
  connections in order of `stream`. The table is empty afterwards. It sets no
  `end` of its own: a FIN that was captured still ends its direction.
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
- `end` says the direction is over after `data`.

**`TCPStreamStats(segments, streams, delivered, retransmitted, out_of_order, missing, conflicts, ignored, evicted, pending, held)`**
— a named tuple of counts: TCP segments taken; connections numbered so far;
octets handed out; octets dropped as copies of delivered or held ones;
segments that arrived ahead of a hole; octets given up on; held octets that a
later copy disagreed with; segments and acknowledgments set aside (octets
before the start or beyond a FIN, a reset out of sequence, a SYN-ACK that
contradicts the connection, an acknowledgment beyond everything seen, a
segment in an IP fragment that was not reassembled); connections forgotten at
`max_streams` or for age; connections in the table; octets held out of order
at the moment.

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
   not beyond the furthest octet seen from that sender, every hole before it
   is given up and what is held up to it is delivered, in the frame that
   carried the acknowledgment and before that frame's own octets. One that
   falls inside a hole gives up only the part before it. An acknowledgment
   beyond everything seen from the sender changes nothing and is counted in
   `ignored`: it cannot be told from a forged one, and believing it would let
   one segment make every later octet look like a retransmission. The
   acknowledgment of a FIN covers the FIN.
8. **FIN ends a direction** at its position; octets claimed beyond it are
   dropped. **RST ends the connection**, both directions, unless its sequence
   number is behind what was already delivered, when it is ignored. A reset in
   sequence is taken at its word: held octets come out with their `missing`,
   and the next segments on those addresses start a new stream.
9. **A SYN that is not a retransmission of the connection's own starts a new
   connection** on the same addresses and ends the connection it replaces.
10. **Not done**: the checksum is not verified; the urgent pointer is ignored
    and its octet delivered in place (RFC 6093); a segment inside an IP
    fragment that was not reassembled is ignored.

A zero-length segment with no SYN, FIN or RST delivers nothing and starts no
connection, and is still read for its acknowledgment. A SYN takes one sequence
number before its data and a FIN one after it. A SYN-ACK whose acknowledgment
contradicts the SYN the connection started with is ignored.

## Bounds

Every amount a capture controls has a ceiling. Reaching the last three loses
the wait and never the octets; only the first two drop held octets.

| What the capture controls | Ceiling | At the ceiling |
| --- | --- | --- |
| connections tracked | `max_streams` (1,024) | the least recently active is forgotten, its held octets dropped, `evicted` |
| capture time a connection may be silent | `idle_timeout` (300 s) | forgotten when its addresses are next seen, which start a new `stream`; `evicted` |
| octets held out of order over all connections | `max_buffered` (16,777,216), each held piece charged its length plus 64 | the direction that has waited longest gives up its holes and delivers, until the total fits |
| pieces held in one direction | 1,024 | that direction gives up its earliest hole |
| one piece too large for `max_buffered` on its own | `max_buffered` | delivered at once behind a given-up hole |

Silence is `abs(time - last)`: a jump either way past the timeout counts, since
a capture controls its clock and a jump back cannot be told from a gap. A time
of exactly `0.0` (a pcapng simple packet block has none) neither expires a
connection nor keeps it alive.

A segment costs a binary search and a walk over the held pieces it covers, at
most 1,024; held octets are joined once, when a run is delivered.
