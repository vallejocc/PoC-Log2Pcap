log2pcap
========

Tiny source code to log to pcap format, to be able to read/parse/decompose them using Ethereal / wireshark (and other tools).

Here is a explanation about libpcap format that i toke from post long time (today it seems the forum is not online):

Libpcap format has a file header, followed by the packets, with each
packet consisting of a packet header followed immediately by the data in
the packet, with no padding between the file header and the first packet
header, the packet header and the packet data, or the packet data and
the header of the next packet, if any.

The file header consists of, in order:

	a 32-bit "magic number";

	a 16-bit major version number;

	a 16-bit minor version number;

	a 32-bit "time zone offset" field that's actually not used, so
	you can (and probably should) just make it 0;

	a 32-bit "time stamp accuracy" field that's not actually used,
	so you can (and probably should) just make it 0;

	a 32-bit "snapshot length" field;

	a 32-bit "link layer type" field.

The magic number has the value hex a1b2c3d4.  All the fields can be
written in either big-endian or little-endian format; the magic number
is one of those fields, so the program reading the file (tcpdump,
Ethereal, whatever) can infer from that fields value, when it reads it,
whether the file was written in the same byte order as the native byte
order of the machine reading the file or in the opposite byte order, and
can byte-swap the values if they're written in the opposite byte order
(both libpcap, the library tcpdump and many other programs use to read
those files, and the library Ethereal and the programs that come with it
use to read the file, do so).

All numbers in the headers are usually written in the byte order of the
processor on whatever device is saving the frames.

The major version number should have the value 2.

The minor version number should have the value 4.

The "time zone offset" and "time stamp accuracy" fields should both be
zero.

The "snapshot length" field should be the maximum number of bytes per
packet that will be captured.  If the entire packet is captured, make it
65535; if you only capture, for example, the first 64 bytes of the
packet, make it 64.

The link-layer type depends on the type of link-layer header that the
packets in the capture file have:

	0		BSD loopback devices, except for later OpenBSD
	1		Ethernet, and Linux loopback devices
	6		802.5 Token Ring
	7		ARCnet
	8		SLIP
	9		PPP
	10		FDDI
	100		LLC/SNAP-encapsulated ATM
	101		"raw IP", with no link
	102		BSD/OS SLIP
	103		BSD/OS PPP
	104		Cisco HDLC
	105		802.11
	108		later OpenBSD loopback devices (with the AF_
			value in network byte order)
	113		special Linux "cooked" capture
	114		LocalTalk

If you need a new type for a new link-layer header, send mail to
tcpdump-workers at tcpdump.org asking for one; do *not* pick one yourself,
as you may pick one that's already in use, or reserved for future use.

Immediately following that header are the actual frames.

Each frame consists of a frame header followed by the raw bytes of the
frame.

The frame header consists of:

	a time stamp, consisting of:

		a UNIX-format time-in-seconds when the packet was
		captured, i.e. the number of seconds since January 1,
		1970, 00:00:00 GMT (that's GMT, *NOT* local time!);

		the number of microseconds since that second when the
		packet was captured;

	a 32-bit value giving the number of bytes of packet data that
	were captured;

	a 32-bit value giving the actual length of the packet, in bytes
	(which may be greater than the previous number, if you're not
	saving the entire packet).

All those numbers must be in the same byte order as the numbers in the
file header.
