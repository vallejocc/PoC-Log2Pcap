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

void main()
{
  FILE * f;
  
  if(f = fopen("sample.ether","w+b"))
  {
    InitLibpcapEthernetCaptureFileHeader(f,myappend);
   
    LogPacket2Libpcap(f,myappend,myUNIXtimeinsec,"lalalala",8);
    LogPacket2Libpcap(f,myappend,myUNIXtimeinsec,"lylylyly",8);
    LogPacket2Libpcap(f,myappend,myUNIXtimeinsec,"lililili",8);
    LogPacket2Libpcap(f,myappend,myUNIXtimeinsec,"lqlqlqlq",8);
    LogPacket2Libpcap(f,myappend,myUNIXtimeinsec,"lelele",6);

    fclose(f);
  }  
}
