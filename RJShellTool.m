/*
 *  RJShellTool.m
 *  
 *
 *  Created by zhou hongyu on 08-2-26.
 *  Modified by Yin Hou in Aug 2010, Jan 2011
 *  Hongyu Zhou <hongyv.zhou@gmail.com>
 *  Yin Hou <alanhoucts@Gmail.com>
 *  All rights reserved.
 *
 *	don't forget to modify MD5 values in mainController, whenever you changed this file
 
 
 This file is part of CocoaRJ.
 
 CocoaRJ is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 CocoaRJ is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with CocoaRJ.  If not, see <http://www.gnu.org/licenses/>.
 */



#import <SystemConfiguration/SCNetworkConfiguration.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/bpf.h>
#include <net/if.h>
#include <string.h>
#include <sys/select.h>
#include <signal.h>

#include "md5.h"
#include "blog.h"
#include "myerr.h"

#define ETHERTYPE_8021X			0x888e
#define EAPOL_Packet				0x00
#define EAPOL_Start				0x01
#define EAPOL_Logoff				0x02
#define EAP_Request				1
#define EAP_Response				2
#define EAP_Success				3
#define EAP_Failure				4
#define EAP_TYPE_Identity			1
#define EAP_TYPE_MD5Challenge		4

typedef unsigned char 		int8;
typedef unsigned short 	int16;
typedef unsigned long 		int32;

struct bpf_insn insns[] = {
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),								//type
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_8021X, 0, 1),			//check if it is an 802.1X package，yes ->0,no ->1
	BPF_STMT(BPF_RET+BPF_K, (u_int)-1),								// 0
	BPF_STMT(BPF_RET+BPF_K, 0),										// 1
};

//EAPOL on Ethernet format
typedef struct EAPOLforEthernet {
	int16		ethertype;
	int8 		version;
	int8 		type;
	int16 		length;
} EAPOL;

//EAP format
typedef struct EAPformat {				
	int8 		code;
	int8 		id;
	int16 		length;
	int8 		type;
}__attribute__((packed)) EAP;

typedef union {
	u_int16_t	ulValue;
	u_int8_t    btValue[2];
} ULONG_BYTEARRAY;

ULONG_BYTEARRAY  m_serialNo;		//s/n, initialized when recived an Authentication-Success-packet
ULONG_BYTEARRAY  m_key;				

unsigned char pad[144] = {          //Ruijie OEM Extra （V2.56）    by soar
          ////////////////////////////////////////////////////////////////////////////
          //
          // OEM Extra
          // abs_addr: 0x12 --> 0x28
          // rel_addr: 0 --> 22 (23 Bytes)
          0xff,0xff,0x37,0x77,              // Encode( 0x00,0x00,0x13,0x11 )     Ruijie OEM Mark
          0x7f,                             // Encode( 0x01/00    EnableDHCP flag )
          0x00,0x00,0x00,0x00,              // Encode( IP )
          0x00,0x00,0x00,0x00,              // Encode( SubNetMask )
          0x00,0x00,0x00,0x00,              // Encode( NetGate )
          0x00,0x00,0x00,0x00,              // Encode( DNS )
          0x00,0x00,                        // Checksum( )
          
          // abs_addr: 0x29 --> 0x4C 
          // rel_addr: 23 --> 58 (36 Bytes)
          0x00,0x00,0x13,0x11,0x38,0x30,0x32,0x31,0x78,0x2E,0x65,0x78,0x65,0x00,0x00,0x00,      // ASCII 8021x.exe
          0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      //
          0x00,0x00,0x00,0x00,
          
          // abs_addr: 0x4D --> 0x5F
          // rel_addr: 59 --> 77 (19 Bytes)
          0x02,0x38,0x00,0x00,              // 8021x.exe File Version (2.5.6) 
          0x00,                             // unknow flag
          0x00,0x00,0x13,0x11,0x00,0x4A,0x1A,0x28,0x00,0x00,0x13,0x11,0x17,0x22,              // Const strings
          
          // abs_addr: 0x60 --> 0x7F
          // rel_addr: 78 --> 120 (32 Bytes)
		 // 32 bytes spc. Random strings
          0x33,0x43,0x46,0x36,0x36,0x36,0x33,0x42,0x34,0x42,0x33,0x32,0x34,0x42,0x36,0x43,    // 32bits spc. Random strings
          0x39,0x31,0x30,0x34,0x37,0x45,0x35,0x31,0x33,0x43,0x30,0x33,0x38,0x38,0x34,0x39,    // 32bits spc. Random strings
          
          // abs_addr: 0x80 --> 0x8A
          // rel_addr: 78 --> 120 (11 Bytes)
		 // Const strings
		  0x1a,0x0c,0x00,0x00,0x13,0x11,0x18,0x06,0x00,0x00,0x00,       // Const strings
          
          // abs_addr: 0x8B 
          // rel_addr: 121 (1 Byte)
		 // DHCP and first time flag
          0x01,													// DHCP and first time flag
 

          // V2.56 (and upper?) added
          // abs_addr: 0x8C --> 0x93
          // rel_addr: 122 -->  129 (8 Bytes) 
         	 // const strings
          0x1A,0x0E,0x00,0x00,0x13,0x11,0x2D,0x08,  	// Const strings
          // abs_addr: 0x94 --> 0x99
          // rel_addr: 130 -->  135 (6 Bytes)
          // True NIC MAC
          0x00,0x00,0x00,0x00,0x00,0x00,				// True NIC MAC
          // abs_addr: 0x9A --> 0xA1
          // rel_addr: 136 -->  143 (8 Bytes)
		 // Const strings
          0x1A,0x08,0x00,0x00,0x13,0x11,0x2F,0x02   	// Const strings
};

//echo package, send per 20s
char echoPackage[] = {			
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x88,0x8E,0x01,0xBF, 
	0x00,0x1E,
	0xFF,0xFF,0x37,0x77,0x7F,0x9F,0xFF,0xFF,0x00,0x00,
	0xFF,0xFF,0x37,0x77,0x7F,0x9F,0xFF,0xFF,0x00,0x00,
	0xFF,0xFF,0x37,0x77,0x7F,0x3F,0xFF
};

unsigned char m_ip[4] = {0x00, 0x00, 0x00, 0x00};
unsigned char m_netmask[4] = {0x00, 0x00, 0x00, 0x00}; 
unsigned char m_netgate[4]= {0x00, 0x00, 0x00, 0x00};
unsigned char m_dns1[4] = {0x00, 0x00, 0x00, 0x00};

char standardMAC[6]={0x01,0x80,0xc2,0x00,0x00,0x03};		//	standard 802.1X broadcast MAC address
char localMAC[6]={0x00,0x0d,0x93,0x2a,0xd6,0xe0};			// 	loca MAC address


char *nic;
char *name;
char *pass;

unsigned char Rjhash[32];		// The 32 bytes md5hash in MD5-challenge Response packet
unsigned char hex[2];			// b2hex variable

//int 	AUTHEN_TIMES=0;			//认证次数

char 	*buf;
char 	*p;
int8		dstMAC[6]={0,};
int		bpf; 
int		blen=1;

int isIntel(){
	union w{
		int a;
		char b;
		
	}c;
	c.a = 1;
	return (c.b == 1);
}

Boolean setAsDHCPAndRenew(){
	
	Boolean SCNetResult;
	SCPreferencesRef prefs = SCPreferencesCreate(NULL, CFSTR("SystemConfiguration"), NULL);
	CFArrayRef all = SCNetworkSetCopyServices(SCNetworkSetCopyCurrent(prefs));
	SCNetworkInterfaceRef en0_SCNetworkInterfaceRef = NULL;
	SCNetworkServiceRef en0_SCNetServiceRef = NULL;
	for(CFIndex i = CFArrayGetCount(all) - 1; i--; i > -1){
		SCNetworkServiceRef aNetServiceRef = CFArrayGetValueAtIndex(all, i);
//		CFStringRef serviceName = SCNetworkServiceGetName(aNetServiceRef);
//		CFShow(serviceName);
		SCNetworkInterfaceRef aSCNetworkInterfaceRef = SCNetworkServiceGetInterface(aNetServiceRef);
		CFStringRef bsdName = SCNetworkInterfaceGetBSDName(aSCNetworkInterfaceRef);
		if(bsdName != NULL){
			if(CFStringCompare(bsdName, CFSTR("en0"), 0) == kCFCompareEqualTo){
				en0_SCNetworkInterfaceRef = aSCNetworkInterfaceRef;
				en0_SCNetServiceRef = aNetServiceRef;
	//			fprintf(stdout, "en0 in NetServiceRef found! \n");
				fflush(stdout);
				break;
			}
		}
	}
	
//	SCNetworkServiceRef en0_SCNetworkServiceRef = SCNetworkServiceCreate(prefs, en0_SCNetworkInterfaceRef);
	if(en0_SCNetServiceRef == NULL){
		fprintf(stdout, "en0_SCNetServiceRef == NULL error \n");
		fflush(stdout);
		return FALSE;
	} 
	
	//SCNetworkProtocolRef 
	SCNetworkProtocolRef en0_SCNetworkProtocolRef = SCNetworkServiceCopyProtocol (en0_SCNetServiceRef, kSCNetworkProtocolTypeIPv4);  
	if(en0_SCNetworkProtocolRef == NULL){
		fprintf(stdout, "en0_SCNetworkProtocolRef == NULL error \n");
		fflush(stdout);
		return FALSE;
	} 
	
	CFDictionaryRef en0_ProtocolConfigureDict = NULL;
	en0_ProtocolConfigureDict = SCNetworkProtocolGetConfiguration(en0_SCNetworkProtocolRef);
//	CFShow(en0_ProtocolConfigureDict);
	CFMutableDictionaryRef new_en0_ProtocolConfigureDict = CFDictionaryCreateMutableCopy(0, 0, en0_ProtocolConfigureDict);
	
	CFBooleanRef value___INACTIVE__ = NULL;
	Boolean isPresent___INACTIVE__ = CFDictionaryGetValueIfPresent(en0_ProtocolConfigureDict, CFSTR("__INACTIVE__"), (const void**)&value___INACTIVE__);
	if(isPresent___INACTIVE__ == TRUE){
		if(CFBooleanGetValue(value___INACTIVE__) == TRUE){
			fprintf(stdout, "Please change your configure of Ethernet to 'Active'.\n");
			fflush(stdout);
			return FALSE;
		//	CFDictionaryRemoveValue(new_en0_ProtocolConfigureDict, CFSTR("__INACTIVE__"));
		//	CFShow(new_en0_ProtocolConfigureDict);
		}
	}	
	CFStringRef value_kSCPropNetIPv4ConfigMethod = NULL;
	Boolean isPresent_kSCPropNetIPv4ConfigMethod = CFDictionaryGetValueIfPresent(en0_ProtocolConfigureDict, kSCPropNetIPv4ConfigMethod, (const void**)&value_kSCPropNetIPv4ConfigMethod);
	if(isPresent_kSCPropNetIPv4ConfigMethod == TRUE){
		if(CFStringCompare(value_kSCPropNetIPv4ConfigMethod, CFSTR("DHCP"), 0) == kCFCompareEqualTo){
			
		}
		else{
			fprintf(stdout, "CocoaRJ changed your configure of Ethernet to 'DHCP'.\n");
			fflush(stdout);
			
			CFDictionarySetValue(new_en0_ProtocolConfigureDict, kSCPropNetIPv4ConfigMethod, CFSTR("DHCP"));
			SCNetworkProtocolSetConfiguration(en0_SCNetworkProtocolRef, new_en0_ProtocolConfigureDict);
			
			if(en0_ProtocolConfigureDict == NULL){
				fprintf(stdout, "en0_ProtocolConfigureDict == NULL error \n");
				fflush(stdout);
				return FALSE;
			} 
			else{
				//		CFShow(en0_ProtocolConfigureDict);
				//		CFShow(new_en0_ProtocolConfigureDict);
			}	
		}
	}
	else{
		fprintf(stdout, "CocoaRJ changed your configure of Ethernet to DHCP.\n");
		fflush(stdout);
		
		CFDictionarySetValue(new_en0_ProtocolConfigureDict, kSCPropNetIPv4ConfigMethod, CFSTR("DHCP"));
		SCNetworkProtocolSetConfiguration(en0_SCNetworkProtocolRef, new_en0_ProtocolConfigureDict);
		
		if(en0_ProtocolConfigureDict == NULL){
			fprintf(stdout, "en0_ProtocolConfigureDict == NULL error \n");
			fflush(stdout);
			return FALSE;
		} 
		else{
			//		CFShow(en0_ProtocolConfigureDict);
			//		CFShow(new_en0_ProtocolConfigureDict);
		}	
	}

	SCNetResult = SCNetworkInterfaceForceConfigurationRefresh(en0_SCNetworkInterfaceRef);
	if(SCNetResult == FALSE){
		fprintf(stdout, "SCNetworkInterfaceForceConfigurationRefresh == FALSE error \n");
		fflush(stdout);
		return FALSE;
	} 
	SCPreferencesCommitChanges(prefs);
	SCPreferencesApplyChanges(prefs);
	return TRUE;
}

static OSStatus GetToolPath(CFStringRef bundleID, CFStringRef toolName, char *toolPath, size_t toolPathSize)
{
    OSStatus    err;
    CFBundleRef bundle;
    Boolean     success;
    CFURLRef    toolURL;
    
    assert(bundleID != NULL);
    assert(toolName != NULL);
    assert(toolPath != NULL);
    assert(toolPathSize > 0);
    
    toolURL = NULL;
    
    err = noErr;
    bundle = CFBundleGetBundleWithIdentifier(bundleID);
    if (bundle == NULL) {
        err = coreFoundationUnknownErr;
    }
    if (err == noErr) {
        toolURL = CFBundleCopyAuxiliaryExecutableURL(bundle, toolName);
        if (toolURL == NULL) {
            err = coreFoundationUnknownErr;
        }
    }
    if (err == noErr) {
        success = CFURLGetFileSystemRepresentation(toolURL, true, (UInt8 *) toolPath, toolPathSize);
        if ( ! success ) {
            err = coreFoundationUnknownErr;
        }
    }
    
    if (toolURL != NULL) {
        CFRelease(toolURL);
    }
    
    return err;
}



/*
	convert 1Byte hex to two ASCII values
	0xa5 --> 'a' '5' stored to hex[0][1]
 */

void b2hex(unsigned char byte)
{
	char b2h_table[]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	hex[0] = b2h_table[0x0f & (byte>>4)];
	hex[1] = b2h_table[0x0f & byte];
}

/*
	make MD5-challenge Response package 32bytes, base on 16bytes MD5 seed and ./8021x.exe

	abs_addr:0x60 --> 0x7F;
	rel_addr:78 --> 120
 */
void hash8021x(unsigned char* md5get)
{
	char        _8021Path[PATH_MAX];
	NSString *      bundleID;
	bundleID = [[NSBundle mainBundle] bundleIdentifier];

	GetToolPath((CFStringRef)bundleID, CFSTR("8021x.exe"),  _8021Path,  sizeof(_8021Path));
	
	FILE* rjfile = fopen( _8021Path, "rb");

	fseek(rjfile, 0x1000, 0);

//	int bufferSize = 0x4a00;
	unsigned char tableC[144]; 
	unsigned char temp[0x4a10];
	unsigned char buff[0x4a00];
	MD5_CTX context;
	int i;
	int index = 0;
	for( i=0; i<8; i++) {
		tableC[index] = md5get[i*2];
		index++;
		
		memcpy(temp,md5get, 16);
		fread(buff,0x4a00, 1, rjfile);
		memcpy(temp+0x10, buff, 0x4a00);

		MD5Init(&context);

		MD5Update(&context, temp, 0x4a10);
		MD5Final(tableC+index, &context);
		index += 0x10;
		tableC[index]=md5get[i*2+1];
		index++;
	}
	unsigned char md5_final[16];

		MD5Init(&context);
		MD5Update(&context, tableC, 144); 
		MD5Final(md5_final, &context);

	for (i = 0; i<16; i++)
	{
		b2hex(md5_final[i]);
		memcpy(Rjhash+2*i,hex,2);
	}

}

void sig_intr(int signo);		//send logoff package on exit with Ctrl+C




int main(int argc, char * argv[])
{
	fprintf(stdout, "pid<<<%ld>>>pid\n", (long) getpid());
	fflush(stdout);	
	
	if(setAsDHCPAndRenew() == FALSE){
		fprintf(stdout, "Set As DHCP fail error!\n");
		fflush(stdout);
		return 0;
	}
	

//	fprintf(stdout, "BASHelperToolMain\n");
//FILE* fpout=freopen("log","w",stdout); 
//	[filehandle writeData:[@"test" dataUsingEncoding:NSUTF8StringEncoding]];
	int offset;
	char challengelen;
	
	struct ifreq ifr;
	
	// struct bpf_program
	/*
	struct bpf_program {
        int bf_len;
        struct bpf_insn *bf_insns;
	};
	*/
	struct bpf_program bpf_pro={4,insns};
	
	struct timeval timeout={1,0};	//BPF 1s timeout
	//unsigned char *bufmd5;
	// ?????
	unsigned char bufmd5[23];		// id(1Byte)+password(6Bytes)+md5seed(16Bytes)
	int8 id;
	unsigned char md5Hash[16];
	MD5_CTX context;
	fd_set readset;
	ULONG_BYTEARRAY uTemp;
	name = argv[1];
	pass = argv[2];
	nic = argv[3];
	int retryCount = atoi(argv[4]);
	
	int namelen=strlen(name);
	int passlen=strlen(pass);
	
	/*
		TODO：check connection
	 */
	
	// bpf0,1,2,3, TODO: automatic choose one avaiable
	if((bpf=open("/dev/bpf2",O_RDWR))==-1)
	{
		fprintf(stdout, "open /dev/bpf2 error\n");
		fflush(stdout);

		exit(1);
	}
	
	// TODO: learning ioctl
	strcpy(ifr.ifr_name, nic);//set BPF network interface
	if(	(-1==ioctl(bpf,BIOCSETIF,&ifr))||(-1==ioctl(bpf,BIOCGBLEN,&blen))|| 
		(-1==ioctl(bpf,BIOCSETF,&bpf_pro))||(-1==ioctl(bpf,BIOCSRTIMEOUT,&timeout))
	)
	{
		fprintf(stdout, "ioctl error\n");
		fflush(stdout);

		close(bpf);
		exit(1);
	}
 
	
	//m_serialNo.ulValue = 0x1000002a; 
	//the initial serial number, a magic number! 
	m_serialNo.ulValue = 0x102a;

	if((buf=(char *)malloc(blen))==NULL)
	{
		fprintf(stdout, "malloc buf error\n");
		fflush(stdout);

		close(bpf);
		exit(1);
	}

	signal(SIGINT,sig_intr);  //exit with Ctrl+C
	signal(SIGTERM,sig_intr);  //send when logoff EAPOL
	signal(SIGQUIT,sig_intr);
 
retry:
	if(retryCount<=0)
		exit(0);
	retryCount--;
	if(retryCount>0){
		fprintf(stdout, "Ruijie authentication start... (Retry Left:%d)\n", retryCount);
				fflush(stdout);

	}
	else{
			fprintf(stdout, "Ruijie authentication start... \n");
			fflush(stdout);
			}
		


	//create 802.1X EAPOL-Start frame
	//fprintf(stdout, "send EAPOL_Start packet... \n");

	memset(buf,0,blen);
	memcpy(buf,standardMAC,6);
	((EAPOL *)(buf+12))->ethertype=htons(0x888E);
	((EAPOL *)(buf+12))->version=1;
	((EAPOL *)(buf+12))->type=EAPOL_Start; // 0x01
	((EAPOL *)(buf+12))->length=0;

	InitializeBlog(m_ip, m_netmask, m_netgate, m_dns1);
	FillNetParamater( &pad[0x05] );	 	
	
	memcpy( pad+130, localMAC, 6);
	memcpy(buf+12+sizeof(EAPOL),pad, sizeof(pad));
	//memcpy(buf+0x17, pad, 0x90);

	//???
	if(1000 != write(bpf,buf,1000)) //发送802.1X的EAPOL-Start帧
	{
		fprintf(stdout, "write EAPOL_Start error\n");
		fflush(stdout);

		goto retry;
	}
	//fprintf(stdout, "done!\n");
 
	//read EAP Request Identity frame
	//fprintf(stdout, "Reading EAP Request Identity... \n");
	FD_ZERO(&readset);
	FD_SET(bpf, &readset);
	ioctl(bpf,BIOCFLUSH);
 
	/*
	if (FD_ISSET(bpf, &readset))
	{
		fprintf(stdout, "FD_ISSET is SET!!!!!\n");
	}	
	*/
	if( 0 > select(bpf+1,&readset,NULL,NULL,&timeout) )
	{
		//fprintf(stdout, "%d\n",offset);
		fprintf(stdout, "select read EAP Request Identiry\n");
		fflush(stdout);

		goto retry;
	}

	if(-1==read(bpf,buf,blen))
	{
		fprintf(stdout, "read EAP Request Identity error\n");
		fflush(stdout);

		goto retry;
	}

	p=buf+((struct bpf_hdr *)buf)->bh_hdrlen;

	if(	(((EAPOL *)(p+12))->type!=EAPOL_Packet)||
		(((EAP *)(p+12+sizeof(EAPOL)))->code!=EAP_Request)||
		(((EAP *)(p+12+sizeof(EAPOL)))->type!=EAP_TYPE_Identity) )
	{
		fprintf(stdout, "Connection error! \n");
		fflush(stdout);

		goto retry;
	}
	id=((EAP *)(p+12+sizeof(EAPOL)))->id;
	memcpy(dstMAC,p+6,6);
	//fprintf(stdout, "done!\n");
 
	//create EAP Response Identity frame
	//fprintf(stdout, "send EAP Response Identity packet... \n");
	memset(buf,0,blen);
	memcpy(buf,dstMAC,6);
	((EAPOL *)(buf+12))->ethertype=htons(0x888E);
	((EAPOL *)(buf+12))->version=1;
	((EAPOL *)(buf+12))->type=EAPOL_Packet; //0x00
	((EAPOL *)(buf+12))->length=htons(sizeof(EAP)+namelen);
	((EAP *)(buf+12+sizeof(EAPOL)))->code=EAP_Response; //2
	((EAP *)(buf+12+sizeof(EAPOL)))->id=id;
	((EAP *)(buf+12+sizeof(EAPOL)))->length=htons(sizeof(EAP)+namelen);
	((EAP *)(buf+12+sizeof(EAPOL)))->type=EAP_TYPE_Identity;
	memcpy(buf+12+sizeof(EAPOL)+sizeof(EAP),name,namelen);
	//memcpy(pad+78,random_1,sizeof(random_1));
	memcpy(buf+12+sizeof(EAPOL)+sizeof(EAP)+namelen,pad,sizeof(pad));
	
	if(1000!=write(bpf,buf,1000)) //send EAP Response Identity frame
	{
		fprintf(stdout, "write EAP Response Identity error\n");
		fflush(stdout);

		goto retry;
	}
	//fprintf(stdout, "done!\n");
 
	//read EAP Request MD5-Challenge frame
	//fprintf(stdout, "Reading EAP Request MD5-Challenge...\n");
	FD_ZERO(&readset);
	FD_SET(bpf, &readset);
	ioctl(bpf,BIOCFLUSH);
	if(0 > select(bpf+1,&readset,NULL,NULL,&timeout))
	{
		fprintf(stdout, "select read EAP Request MD5-Challenge\n");
		fflush(stdout);

		goto retry;
	}
	if(-1==read(bpf,buf,blen))
	{
		fprintf(stdout, "read EAP Request MD5-Challenge errorr\n");
		fflush(stdout);

		goto retry;
	}

	p=buf+((struct bpf_hdr *)buf)->bh_hdrlen;
	//fprintf(stdout, "type:%x\t code: %x\t type:%x\n",((EAPOL *)(p+12))->type, ((EAP *)(p+12+sizeof(EAPOL)))->code,((EAP *)(p+12+sizeof(EAPOL)))->type);

	if(	(((EAPOL *)(p+12))->type!=EAPOL_Packet)||
		(((EAP *)(p+12+sizeof(EAPOL)))->code!=EAP_Request)||
		(((EAP *)(p+12+sizeof(EAPOL)))->type!=EAP_TYPE_MD5Challenge) )
	{
		fprintf(stdout, "EAP Request MD5-Challenge format error! \n");
		fflush(stdout);

		goto retry;
	}

	id=((EAP *)(p+12+sizeof(EAPOL)))->id;    // get id
	//fprintf(stdout, "The ID is: %x\n", id); 
	challengelen=*((char *)(p+12+sizeof(EAPOL)+sizeof(EAP)));  // always be 0x10
	//fprintf(stdout, "challengelen: %x \n",challengelen);
	
	
	/*
	if( (bufmd5=(unsigned char *)malloc(1+challengelen+passlen))==NULL )
	{
		fprintf(stdout, "malloc bufmd5 error\n");
		close(bpf);
		exit(1);
	}
	*/
	
	/*The Response Value is the one-way hash calculated over a stream of
      octets consisting of the Identifier, followed by (concatenated
      with) the "secret", followed by (concatenated with) the Challenge
      Value.  The length of the Response Value depends upon the hash
      algorithm used (16 octets for MD5).please refer to RFC1994*/
	
	memset(bufmd5,0,1+challengelen+passlen);
	*bufmd5=id;  // get id;
	//bufmd5[0]=id; 
	memcpy(bufmd5+1,pass,passlen);  // passward
	memcpy(bufmd5+1+passlen,p+12+sizeof(EAPOL)+sizeof(EAP)+1,challengelen); // 密钥
	
	// md5 unpack
	unsigned char md5_temp[16];	
	memcpy(md5_temp,p+12+sizeof(EAPOL)+sizeof(EAP)+1,16);

	hash8021x(md5_temp);
	
	MD5Init(&context);
	//md5 
	MD5Update(&context, bufmd5, 1+challengelen+passlen); 
	MD5Final(md5Hash, &context); 
 
	//create EAP Response MD5-Challenge frame
	//fprintf(stdout, "send EAP Response MD5-Challenge packet... \n");
	memset(buf,0,blen);
	memcpy(buf,dstMAC,6);
	((EAPOL *)(buf+12))->ethertype=htons(0x888E);
	((EAPOL *)(buf+12))->version=1;
	((EAPOL *)(buf+12))->type=EAPOL_Packet; //0x00
	//((EAPOL *)(buf+12))->length=htons(sizeof(EAP)+namelen+challengelen+1);//here "1" is the value-size of EAP
	
	if(isIntel()){
		((EAPOL *)(buf+12))->length=(0x1e00 - (8 - namelen)*0x0100);
	}
	else{
		((EAPOL *)(buf+12))->length=(0x1e - (8 - namelen));
	}
	((EAP *)(buf+12+sizeof(EAPOL)))->code=EAP_Response;  
	((EAP *)(buf+12+sizeof(EAPOL)))->id=id;  
	((EAP *)(buf+12+sizeof(EAPOL)))->length=htons(sizeof(EAP)+namelen+challengelen+1); //0x10?
	((EAP *)(buf+12+sizeof(EAPOL)))->type=EAP_TYPE_MD5Challenge; 
	*(char *)(buf+12+sizeof(EAPOL)+sizeof(EAP))=16;			//md5 hash length
	
	memcpy(buf+12+sizeof(EAPOL)+sizeof(EAP)+1,md5Hash,16);
	memcpy(buf+12+sizeof(EAPOL)+sizeof(EAP)+1+16,name,namelen);
	
	memcpy(pad+78,Rjhash,sizeof(Rjhash));		// write 32bytes(78->120) md5hash
	FillNetParamater( &pad[0x05]);
	memcpy( pad+130, localMAC, 6);	
	memcpy(buf+12+sizeof(EAPOL)+sizeof(EAP)+1+16+namelen,pad,sizeof(pad));
	
	
	
	if(1000!=write(bpf,buf,1000))	//发送EAP Response MD5-Challenge帧
	{
		fprintf(stdout, "write EAP Response MD5-Challenge error\n");
		fflush(stdout);

		goto retry;
	}
// 	fprintf(stdout, "After MD5Final! \n");

 
	//read EAP success/fail frame
	//fprintf(stdout, "Reading EAP success or fail...\n");
	FD_ZERO(&readset);
	FD_SET(bpf, &readset);
	ioctl(bpf,BIOCFLUSH);
	if(0 > select(bpf+1,&readset,NULL,NULL,&timeout))
	{
		fprintf(stdout, "select read EAP authentication result\n");
		fflush(stdout);

		goto retry;
	}
	if(-1==read(bpf,buf,blen))
	{
		fprintf(stdout, "read EAP authentication result error\n");
		fflush(stdout);

		goto retry;
	}
	
	p=buf+((struct bpf_hdr *)buf)->bh_hdrlen;
	/*
	if( (((EAPOL *)(p+12))->type!=EAPOL_Packet)||(((EAP *)(p+12+sizeof(EAPOL)))->id!=id) )
	{
		fprintf(stdout, "EAP result packet error! \n");
		fflush(stdout);

		goto retry;
	}
*/
	// read server info
	char msg[0x88];		
	memcpy(msg, p+0x17, 0x88);
	FILE *fp;
	fp = fopen("smsg","w");
	fwrite(msg, sizeof(msg), 1, fp);
	fclose(fp);
//	fprintf(stdout, "Ruijie server message: \n");
//	fflush(stdout);

	// gb2312 --> utf-8
//	fprintf(stdout, "msg_cn<<<%s>>>msg_cn\n", msg);
	system("cat smsg | iconv -f gb2312 -t utf-8");
	fprintf(stdout, "\n");
	fflush(stdout);

	

	
	if(((EAP *)(p+12+sizeof(EAPOL)))->code==EAP_Success)
	{

		
		//fprintf(stdout, "EAP Authentication success! \n");
		fprintf(stdout, "Ruijie authentication success! \n");
		fflush(stdout);

		//AUTHEN_TIMES++;									
		offset=ntohs( *((int16*)(p+0x10)) ); 
		uTemp.ulValue = *((int16 *)(p+(0x12+offset)-0x07));
		
		m_key.btValue[0] = Alog(uTemp.btValue[0]); 
		m_key.btValue[1] = Alog(uTemp.btValue[1]); 
		
	//	 DHCP renew, it's ugly, I know that:-|
	//	system("ifconfig set en0 DHCP");
	
	//	system("ifconfig en0 down");
	//	system("ifconfig en0 up");

	//	system("ipconfig set en0 BOOTP");
	//	system("ipconfig set en0 DHCP");

		if(setAsDHCPAndRenew() == FALSE){
			fprintf(stdout, "Renew DHCP fail error!\n");
			fflush(stdout);
		}

		BOOL hadFun = NO;
		if (system("ifconfig en0| grep 'inet '| grep ' 169.' > /dev/null")) {
			fprintf(stdout, "IP address: ");
			fflush(stdout);
			system("ifconfig en0| grep 'inet '| cut -d ' ' -f 2");
			fflush(stdout);
			fprintf(stdout, "Have Fun :)\n");
			fflush(stdout);
			hadFun = YES;

		}
		/*
		if (system("ifconfig en0| grep 'inet '| grep ' 169.' >> /dev/null")) {// if 169 exists, system = 0
			fprintf(stdout, "IP address: ");
			fflush(stdout);
			system("ifconfig en0| grep 'inet '| cut -d ' ' -f 2");
			fflush(stdout);
			fprintf(stdout, "Have Fun :)\n");
			fflush(stdout);
			hadFun = YES;
		}
		*/
		int i = 20;
		while(1) {

			fprintf(stdout, "echo\n");
			fflush(stdout);
			if((i%8 == 0)&&(hadFun == NO)){
				if (!system("ifconfig en0| grep 'inet '| grep ' 169.' > /dev/null")) {
					fprintf(stdout, "IP address: ");
					fflush(stdout);
					system("ifconfig en0| grep 'inet '| cut -d ' ' -f 2");
					fflush(stdout);
		//			system("ifconfig en0 down");
		//			system("ifconfig en0 up");
					if(setAsDHCPAndRenew() == FALSE){
						fprintf(stdout, "Renew DHCP Fail error!\n");
						fflush(stdout);
					}
					else{
						fprintf(stdout, "No public IP address distributed, DHCP renewed! \n");
						fflush(stdout);
					}
				}
				else{
					if(hadFun == NO){
						fprintf(stdout, "IP address: ");
						fflush(stdout);
						system("ifconfig en0| grep 'inet '| cut -d ' ' -f 2");
						fflush(stdout);
						fprintf(stdout, "Have Fun :)\n");
						fflush(stdout);
						hadFun = YES;
					}
				}
			}
			if(i==0){
				ULONG_BYTEARRAY uCrypt1,uCrypt2,uCrypt1_After,uCrypt2_After; 
				m_serialNo.ulValue++; 
				//m_serialNo is initialized at the beginning of main() of main.c, and 
				//m_key is initialized in main.c when the 1st Authentication-Success packet is received. 
				uCrypt1.ulValue = m_key.ulValue + m_serialNo.ulValue; 
				uCrypt2.ulValue = m_serialNo.ulValue; 
				memcpy( echoPackage, dstMAC, 6 ); 
				uCrypt1_After.ulValue = htonl( uCrypt1.ulValue ); 
				uCrypt2_After.ulValue = htonl( uCrypt2.ulValue ); 
				
				echoPackage[0x1a] = Alog(uCrypt1_After.btValue[0]); 
				echoPackage[0x1b] = Alog(uCrypt1_After.btValue[1]);
				echoPackage[0x24] = Alog(uCrypt2_After.btValue[0]); 
				echoPackage[0x25] = Alog(uCrypt2_After.btValue[1]);
				while(write(bpf,echoPackage, 0x2d)!=0x2d);
				ioctl(bpf,BIOCFLUSH);
				i = 20;
			}
			i--;
			sleep(1);
		}
	}
	else {
		fprintf(stdout, "Ruijie authentication fail! \n");
		fflush(stdout);

		goto retry;
	}
	close(bpf);//shouldnt reach here
	return 0;
}


void sig_intr(int signo)
{
	if(buf!=NULL)
	{
 	//create 802.1X EAPOL-Logoff frame
		memset(buf,0,blen);
		if( (dstMAC[0]==0)&&(dstMAC[1]==0)&&(dstMAC[2]==0) )
			memcpy(buf,standardMAC,6); 
		else
			memcpy(buf,dstMAC,6);
	
		((EAPOL *)(buf+12))->ethertype=htons(0x888E);
		((EAPOL *)(buf+12))->version=1;
		((EAPOL *)(buf+12))->type=EAPOL_Logoff;
		((EAPOL *)(buf+12))->length=0;
		if((12+sizeof(EAPOL))!= write(bpf,buf,12+sizeof(EAPOL))) //send 802.1X EAPOL-Logoff frame
		{
			fprintf(stdout, "write EAPOL_Logoff error");
			fflush(stdout);

		}

   }
	fprintf(stdout, "log off\n");
	fflush(stdout);

   _exit(0);
}

