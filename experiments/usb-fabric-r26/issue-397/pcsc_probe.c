/* Real Linux guest PC/SC-to-QEMU CCID synthetic card transport oracle.
 * Never logs ATR raw bytes, APDU payload, certificate identities or PINs.
 */
#define _POSIX_C_SOURCE 200809L
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int main(void) {
 SCARDCONTEXT ctx=0;
 LONG err=SCardEstablishContext(SCARD_SCOPE_SYSTEM,NULL,NULL,&ctx);
 if(err!=SCARD_S_SUCCESS){
  printf("R26_N5B_PCSC_CONTEXT=RED code=%ld\n",(long)err);
  return 2;
 }
 puts("R26_N5B_REAL_GUEST_PCSC_CONTEXT=PASS");fflush(stdout);
 LONG last=SCARD_E_NO_READERS_AVAILABLE;
 SCARDHANDLE card=0;
 DWORD proto=0;
 for(int attempt=0;attempt<45;attempt++){
  DWORD size=0;
  last=SCardListReaders(ctx,NULL,NULL,&size);
  if(last==SCARD_S_SUCCESS && size>2 && size<4096){
   char *names=calloc(size,1);
   if(!names){SCardReleaseContext(ctx);return 3;}
   last=SCardListReaders(ctx,NULL,names,&size);
   if(last==SCARD_S_SUCCESS && names[0]){
    puts("R26_N5B_REAL_GUEST_USB_CCID_PCSC_READER_PRESENT=PASS");fflush(stdout);
    last=SCardConnect(ctx,names,SCARD_SHARE_SHARED,
                       SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1,&card,&proto);
    free(names);
    if(last==SCARD_S_SUCCESS)break;
   }else free(names);
  }
  sleep(1);
 }
 if(!card){
  printf("R26_N5B_GUEST_PCSC_CONNECT_CARD=RED code=%ld\n",(long)last);
  SCardReleaseContext(ctx);
  return 4;
 }
 puts("R26_N5B_REAL_GUEST_PCSC_CARD_CONNECTED=PASS");fflush(stdout);
 char reader[256];DWORD readerSize=sizeof(reader),state=0,atrLen=64;
 unsigned char atr[64];
 err=SCardStatus(card,reader,&readerSize,&state,&proto,atr,&atrLen);
 if(err!=SCARD_S_SUCCESS || atrLen==0 || atrLen>64){
  puts("R26_N5B_GUEST_PCSC_ATR=RED");
  SCardDisconnect(card,SCARD_LEAVE_CARD);
  SCardReleaseContext(ctx);
  return 5;
 }
 printf("R26_N5B_REAL_GUEST_PCSC_ATR_PRESENT=PASS length=%lu\n",(unsigned long)atrLen);
 fflush(stdout);
 err=SCardBeginTransaction(card);
 if(err!=SCARD_S_SUCCESS){puts("R26_N5B_GUEST_CARD_TRANSACTION=RED");return 6;}
 // SELECT MF on a purely synthetic virtual smart card. A non-9000 SW
 // is permitted: transport is proven by a valid card-originated response,
 // but applet selection semantics are not accepted without SW=9000.
 const unsigned char apdu[]={0x00,0xA4,0x00,0x0C,0x02,0x3F,0x00};
 unsigned char response[512];DWORD recvLen=sizeof(response);
 const SCARD_IO_REQUEST *pci=(proto==SCARD_PROTOCOL_T1)?SCARD_PCI_T1:SCARD_PCI_T0;
 err=SCardTransmit(card,pci,apdu,sizeof(apdu),NULL,response,&recvLen);
 LONG end=SCardEndTransaction(card,SCARD_LEAVE_CARD);
 if(err!=SCARD_S_SUCCESS || end!=SCARD_S_SUCCESS || recvLen<2){
  printf("R26_N5B_GUEST_APDU_TRANSMIT=RED code=%ld len=%lu\n",
    (long)err,(unsigned long)recvLen);
  SCardDisconnect(card,SCARD_LEAVE_CARD);
  SCardReleaseContext(ctx);return 7;
 }
 unsigned int sw=(response[recvLen-2]<<8)|response[recvLen-1];
 printf("R26_N5B_REAL_GUEST_APDU_TRANSPORT=PASS sw=%04x\n",sw);
 if(sw==0x9000)puts("R26_N5B_SYNTHETIC_SELECT_MF=PASS");
 else puts("R26_N5B_SYNTHETIC_SELECT_MF=UNSUPPORTED_CARD_APPLET");
 puts("R26_N5B_TEST_CARD_WRITE_APPLET=NOT_TESTED");
 puts("R26_N5B_REAL_GOVERNMENT_CAC_PROVISIONING=NOT_TESTED");
 fflush(stdout);
 SCardDisconnect(card,SCARD_LEAVE_CARD);
 SCardReleaseContext(ctx);
 return 0;
}
