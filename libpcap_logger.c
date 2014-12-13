#include "libpcap_logger.h"

void InitLibpcapEthernetCaptureFileHeader(void * h,
                                          tappend fa)
{
  tlibpcaphdr hdr;

  hdr.magic = LIBPCAP_MAGIC;
  hdr.mjver = 2;
  hdr.mnver = 4;
  hdr.timezoneoffset = 0;
  hdr.timestampaccuracy = 0;
  hdr.snapshotlen = 0xffff;
  hdr.linklayertype = LINKLAYER_Ethernet;

  fa(h,(unsigned char *)&hdr,sizeof(tlibpcaphdr));
}




void LogPacket2Libpcap(void * h,
                       tappend fa,
                       tUNIXtimeinsec ft,
                       unsigned char * data,
                       unsigned int datasize)
{
  tlibpcappackethdr packethdr;
  
  packethdr.UNIXtime = ft();
  packethdr.nbytescaptured = datasize;  
  packethdr.nbyteslogged = datasize;

  fa(h,(unsigned char *)&packethdr,sizeof(tlibpcappackethdr));
  fa(h,data,datasize);
}
