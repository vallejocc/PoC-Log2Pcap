
//main.c/////////////////////////////////////////////////////////////////////////////////////////////////


#include <windows.h>
#include <stdio.h>
#include "libpcap_logger.h"

void myappend(void * handle,unsigned char * buffer,int buflen)
{
  fwrite(buffer,buflen,1,handle);
}

double myUNIXtimeinsec()
{
  return 0;
}

            unsigned char buf[]=
        {
          0x03,0x06,0x2F,0x1F,0x2D,0xB6,0x91,0x81,0x92,0x31,0x41,0x45,0x43,0x33,0x42,0x30,
          0x31,0x36,0x44,0x44,0x31,0x41,0x42,0x31,0x34,0x44,0x32,0x41,0x45,0x43,0x31,0x32,
          0x31,0x41,0x42,0x39,0x41,0x32,0x45,0x33,0x35,0x39,0x35,0x36,0x30,0x37,0x38,0x44,
          0x35,0x00,0x03,0x0B,0x6A,0x0F,0x56,0x66,0x20,0x4D,0x4D,0x53,0x00,0x6D,0x56,0x66,
          0x20,0x4D,0x4D,0x53,0x00,0x45,0xC6,0x55,0x01,0x87,0x11,0x06,0x83,0x00,0x01,0x87,
          0x07,0x06,0x83,0x00,0x01,0x87,0x10,0x06,0xAB,0x01,0x87,0x08,0x06,0x03,0x6D,0x6D,
          0x73,0x2E,0x76,0x6F,0x64,0x61,0x66,0x6F,0x6E,0x65,0x2E,0x6E,0x65,0x74,0x00,0x01,
          0x87,0x09,0x06,0x89,0x01,0xC6,0x5A,0x01,0x87,0x0C,0x06,0x03,0x00,0x01,0x87,0x0D,
          0x06,0x03,0x77,0x61,0x70,0x40,0x77,0x61,0x70,0x00,0x01,0x87,0x0E,0x06,0x03,0x77,
          0x61,0x70,0x31,0x32,0x35,0x00,0x01,0x01,0x01,0xC6,0x51,0x01,0x87,0x15,0x06,0x83,
          0x07,0x01,0x87,0x07,0x06,0x83,0x00,0x01,0xC6,0x52,0x01,0x87,0x20,0x06,0x03,0x32,
          0x31,0x32,0x2E,0x30,0x37,0x33,0x2E,0x30,0x33,0x32,0x2E,0x30,0x31,0x30,0x00,0x01,
          0x87,0x21,0x06,0x85,0x01,0x87,0x22,0x06,0x83,0x00,0x01,0xC6,0x53,0x01,0x87,0x23,
          0x06,0x03,0x38,0x30,0x00,0x01,0x87,0x24,0x06,0xD0,0x01,0x01,0x01,0x01,0xC6,0x00,
          0x01,0x55,0x01,0x87,0x36,0x00,0x00,0x06,0x03,0x77,0x34,0x00,0x01,0x87,0x00,0x01,
          0x39,0x00,0x00,0x06,0x83,0x07,0x01,0x87,0x00,0x01,0x34,0x00,0x00,0x06,0x03,0x68,
          0x74,0x74,0x70,0x3A,0x2F,0x2F,0x6D,0x6D,0x73,0x63,0x2E,0x76,0x6F,0x64,0x61,0x66,
          0x6F,0x6E,0x65,0x2E,0x65,0x73,0x2F,0x73,0x65,0x72,0x76,0x6C,0x65,0x74,0x73,0x2F,
          0x6D,0x6D,0x73,0x00,0x01,0x01,0x01
        };

void main()
{
  FILE * f;
  
  if(f = fopen("sample.ether","w+b"))
  {
    InitLibpcapEthernetCaptureFileHeader(f,myappend);
   


    LogPacket2Libpcap(f,myappend,myUNIXtimeinsec,buf,sizeof(buf));

    fclose(f);
  }  
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////

#if 0
Hi,
Earlier I had written a tool in VC++ which composes 802.11 frames and stores 
them as ".dat" files. I wish to read/parse/decompose them using Ethereal. 
But, I have to first convert the ".dat" files into ethereal readable format 
(one of them is libpcap).

Somewhere I read on this mailing list (which goes like this):

/************************************

libpcap format has a file header, followed by the packets, with each
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

***************************************************************/

So my question is if I prepend my 802.11 frames which i composed earlier by 
this file header and each frame by the header it mentions.. will ethereal be 
able to decompose the frames?

If there is any better approach to do this, lemme know.

Thanks in advace,

The Tech Ed advantage. You could have it too! 
http://server1.msn.co.in/sp03/teched/index.asp Join right away!
#endif