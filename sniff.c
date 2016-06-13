/*Useful man's are: 7 packet & netdevice*/
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/sockios.h> //may have a warning or something
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <linux/tcp.h>
#include <ctype.h>
#include "hexdump.h"
#include "utils.h"

/*Socket listener program*/
#define DEFAULT_INTERFACE "eth0"
#define DEFAULT_PROTOCOL ETH_P_ALL
#define ETHER_SIZE 14

typedef enum BOOL_ENUM{FALSE=0,TRUE=1} bool;
static int IP_SIZE = 0;

void err_quit(const char *msg);
__be16 process_ether(unsigned char *packet);
__u8 process_ip(unsigned char *packet);
__u8 process_udp(unsigned char *packet);
__u8 process_tcp(unsigned char *packet);

int main(int argc, char *argv[])
{
  char interface[128];
  strcpy(interface,DEFAULT_INTERFACE);
  
  if (argc > 1)
    {
      if (argv[1][0] != '-'){
	strcpy(interface,argv[1]);  //obviously exploitable
      }
    }
  int protocol = DEFAULT_PROTOCOL;
      
  char c;
  int k = 1;
  int protoval;
  bool is_tcp = FALSE;
 
  while (k < argc)
    {
      if (argv[k][0] == '-')
	{
	  if (strcasecmp(argv[k],"-ip") == 0)
	    protocol = ETH_P_IP;
	  else if (strcasecmp(argv[k],"-internal") == 0)
	    protocol = ETH_P_SNAP;
	  else if (strcasecmp(argv[k],"-arp") == 0)
	    protocol = ETH_P_ARP;
	  else if (strcasecmp(argv[k],"-tcp") == 0)
	    {
	      protocol = ETH_P_IP;
	      is_tcp = TRUE;
	    }
	}
      k++;
    }
  printf("[+] Using interface %s...\n",interface);
  char proto_name[256];
  switch(protocol)
    {
    case (ETH_P_ALL):
      strcpy(proto_name,"[ALL]");
      break;
    case (ETH_P_IP):
      strcpy(proto_name,"[IP]");
      break;
    case(ETH_P_SNAP):
      strcpy(proto_name,"[INTERNAL]");
      break;
    case(ETH_P_ARP):
      strcpy(proto_name,"[ARP]");
      break;
    default:
      strcpy(proto_name,"[ALL]");
      break;
    }
  printf("[+] Capturing %s packets...\n",proto_name);


  int raw_sock;
  struct sockaddr_ll sll;
  memset(&sll,0,sizeof(struct sockaddr_ll));  //from linux/if_packet.h
  
  /*Now need to set interface name/characteristics*/
  /*Note: only need sll_protocol & sll_ifindex, use ioctl call to get index*/
  int iface_num;
  /*After socket*/
  
  raw_sock = socket(AF_PACKET,SOCK_RAW,htons(protocol));
  if (raw_sock <= 0)
    err_quit("error creating raw socket");
  

  /*Get I-face number in ifreq structure*/
  struct ifreq ifr;
  memset(&ifr,0,sizeof(struct ifreq));
  
  strcpy(ifr.ifr_name,interface);
  ifr.ifr_name[strlen(interface)] = '\0';
  
  if (ioctl(raw_sock, SIOCGIFINDEX, &ifr) < 0)
    err_quit("error getting device index");
  
  int dev_index = ifr.ifr_ifindex;
  printf("[DEBUG] %s on index %d\n",ifr.ifr_name,ifr.ifr_ifindex);
  

  /*Setting promisc mode*/
  short IFACE_FLAGS;
  
  if (ioctl(raw_sock, SIOCGIFFLAGS, &ifr) < 0)
    err_quit("error getting device flags");
  
  IFACE_FLAGS = ifr.ifr_flags;
  IFACE_FLAGS |= IFF_PROMISC;
  
  ifr.ifr_flags = IFACE_FLAGS;

  if (ioctl(raw_sock,SIOCSIFFLAGS, &ifr) < 0 )
    err_quit("error setting device into promisc mode");
  

  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = dev_index;
  sll.sll_protocol = htons(protocol); //changed from ETH_P_ALL
  
  /*Now we should be able to bind*/
  int res = bind(raw_sock, (struct sockaddr *)&sll, sizeof(struct sockaddr_ll));
  if (res < 0)
    err_quit("error binding to device");

  unsigned char buffer[65535];
  ssize_t packet_len;
  while (1)
    {
      packet_len = recvfrom(raw_sock,buffer,65535,MSG_TRUNC,NULL,NULL);
      printf("[+] Got a %d byte packet [+]\n",packet_len);
      protoval = process_ether(buffer);
      if (protoval == ETH_P_IP)
	{
	  protoval = process_ip(buffer + ETHER_SIZE);
	  if (protoval == IPPROTO_UDP)
	    {
	      protoval = process_udp(buffer + ETHER_SIZE + IP_SIZE);
	    }
	  else if (protoval == IPPROTO_TCP)
	    {
	      protoval = process_tcp(buffer + ETHER_SIZE + IP_SIZE);
	    }
	}
     
      hex_dump(buffer,packet_len,16);
      printf("\n");
    }


  /*from man 7 packet       By  default  all  packets  of the specified protocol type are passed to a packet socket.  To only get packets from a specific interface use bind(2) specifying an address in a struct
       sockaddr_ll to bind the packet socket to an interface.  Only the sll_protocol and the sll_ifindex address fields are used for purposes of binding.
  */
  
  
  return 0;
}

__u8 process_ip(unsigned char *packet)
{
  struct iphdr *ip_hdr;
  ip_hdr = (struct iphdr *)packet;
  
  struct protoent *proto_struct;

  char *ip_source_addr = (char *)malloc(128);
  char *ip_dest_addr = (char *)malloc(128);
  
  inet_ntop(AF_INET, &(ip_hdr->saddr), ip_source_addr,128);
  inet_ntop(AF_INET, &(ip_hdr->daddr), ip_dest_addr, 128);
  
  printf("Source: %s\n",ip_source_addr);
  printf("Destination: %s\n",ip_dest_addr);
  printf("ttl: %d\n",ip_hdr->ttl);
  
  /*Get IP HEADER size so we can process the packet at the right location*/
  IP_SIZE = (int)ip_hdr->ihl;
  IP_SIZE <<= 2; //multiply by 4, for how many bytes
  __u8 ip_protocol = ip_hdr->protocol;
  

  proto_struct = getprotobynumber((int)ip_protocol);

  printf("IP protocol: (Hex: %02x::Dec: %d): %s\n",proto_struct->p_proto,proto_struct->p_proto,upper_case(proto_struct->p_name));
  printf("IP Header Length: %d bytes\n",IP_SIZE);
  

  return ip_protocol;
}

__be16 process_ether(unsigned char *packet)
{
  struct ethhdr *e_hdr;
  
  e_hdr = (struct ethhdr *) packet;  
  unsigned char *src_mac = (unsigned char *)malloc(48);
  unsigned char *dest_mac = (unsigned char *)malloc(48);
  __be16 packet_proto = ntohs(e_hdr->h_proto);
  char proto_name[128];
  
  switch(packet_proto) /*Want more to make it more versatile I guess*/
    {
    case (ETH_P_IP):
      sprintf(proto_name,"IP (0x%04x)",packet_proto);
      break;
    case (ETH_P_ARP):
      sprintf(proto_name,"ARP (0x%04x)",packet_proto);
      break;
    default:
      sprintf(proto_name,"Unkown (0x%04x)",packet_proto);
      break;
    }
  
  bzero(src_mac,48);
  bzero(dest_mac,48);
  strcpy(src_mac,(ether_ntoa((struct ether_addr *)e_hdr->h_source)));
  strcpy(dest_mac,(ether_ntoa((struct ether_addr *)e_hdr->h_dest)));
  
  printf("MAC source: %s\n",src_mac);
  printf("MAC destination: %s\n",dest_mac);
  printf("Protocol: %s\n",proto_name);

  return packet_proto;
}

__u8 process_udp(unsigned char *packet)
{
  struct udphdr *udp_h;
  udp_h = (struct udphdr *)packet;
  


  u_int16_t src_port;
  u_int16_t dst_port;
  u_int16_t udp_len;

#ifdef __FAVOR_BSD  
  src_port = ntohs(udp_h->uh_sport);
  dst_port = ntohs(udp_h->uh_dport);
  udp_len  = ntohs(upd_h->uh_ulen);
#else
  src_port = ntohs(udp_h->source);
  dst_port = ntohs(udp_h->dest);
  udp_len  = ntohs(udp_h->len);
#endif

  printf("Source port: %d\n",src_port);
  printf("Destination port: %d\n",dst_port);
  printf("UDP length: %d\n",udp_len);
}

__u8 process_tcp(unsigned char *packet)
{
  struct tcphdr *tcp_hdr;
  
  /*Not supporting BSD here, could implement later
    All you really need to to chekc the #ifdef __FAVOR_BSD*/
  /*Confusing, I'm using header file linux/tcp.h NOT NETINET/TCP.H*/
  
  tcp_hdr = (struct tcphdr *)packet;
  
  u_int16_t src_port = ntohs(tcp_hdr->source);
  u_int16_t dst_port = ntohs(tcp_hdr->dest);
  u_int32_t seq = tcp_hdr->seq;
  u_int32_t ack_seq = tcp_hdr->ack_seq;
  u_int16_t window = tcp_hdr->window;
  u_int16_t checksum = tcp_hdr->check;
  u_int16_t urg_ptr = tcp_hdr->urg_ptr;


  printf("Source Port: %d\n",src_port);
  printf("Destination Port: %d\n",dst_port);
  
  printf("Flags: ");
  
  if (tcp_hdr->fin)// TCP_FLAG_FIN)
    printf("[FIN] ");
  if (tcp_hdr->syn) //& TCP_FLAG_SYN)
    printf("[SYN] ");
  if (tcp_hdr->ack)//flags & TCP_FLAG_ACK)
    printf("[ACK] ");
  if (tcp_hdr->psh)//flags & TCP_FLAG_PSH)
    printf("[PSH] ");
  if (tcp_hdr->rst)//flags & TCP_FLAG_RST)
    printf("[RST] ");
  if (tcp_hdr->cwr)//flags & TCP_FLAG_CWR)
    printf("[CWR] ");
  if (tcp_hdr->urg)//flags & TCP_FLAG_URG)
    printf("[URG] ");
  if (tcp_hdr->ece)//flags & TCP_FLAG_ECE)
    printf("[ECE] ");

  printf("\n");
  
  
}
void err_quit(const char *msg)
{
  char buffer[1024];
  sprintf(buffer,"[ERROR]: %s\n",msg);
  perror(buffer);
  exit(errno);
}
