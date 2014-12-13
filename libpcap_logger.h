
#ifndef __LIBPCAP_LOGGER_H__
#define __LIBPCAP_LOGGER_H__


typedef void   (*tappend)(void * handle,unsigned char * buffer,int buflen);
typedef double (*tUNIXtimeinsec)();


#define	LINKLAYER_BSD_loopback           0		   //except OpenBSD
#define	LINKLAYER_Ethernet               1		   //and linux loopback
#define	LINKLAYER_802_5                  6		   //token ring
#define	LINKLAYER_ARCnet                 7		  
#define	LINKLAYER_SLIP                   8		  
#define	LINKLAYER_PPP                    9		  
#define	LINKLAYER_FDDI                   10		
#define	LINKLAYER_LLCSNAPencapsulatedATM 100		
#define	LINKLAYER_rawIP                  101		
#define	LINKLAYER_BSDOS_SLIP             102		
#define	LINKLAYER_BSDOS_PPP              103		
#define	LINKLAYER_Cisco_HDLC             104		
#define	LINKLAYER_802_11                 105 //wireless		
#define	LINKLAYER_OpenBSD_loopback       108 //later OpenBSD loopback devices (with the AF_value in network byte order)
#define	LINKLAYER_Linux_cooked           113 //special Linux "cooked" capture
#define	LINKLAYER_LocalTalk              114		



#define LIBPCAP_MAGIC 0xa1b2c3d4

typedef struct _tlibpcaphdr
{
  unsigned int   magic;
  unsigned short mjver;
  unsigned short mnver;
  unsigned int   timezoneoffset;
  unsigned int   timestampaccuracy;
  unsigned int   snapshotlen;
  unsigned int   linklayertype;

}tlibpcaphdr;

typedef struct _tlibpcappackethdr
{
  double UNIXtime;
  unsigned int nbytescaptured;
  unsigned int nbyteslogged;

}tlibpcappackethdr;


void LogPacket2Libpcap(void * h,
                       tappend fa,
                       tUNIXtimeinsec ft,
                       unsigned char * data,
                       unsigned int datasize);


void InitLibpcapEthernetCaptureFileHeader(void * h,
                                          tappend fa);

#endif
