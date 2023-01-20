#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <unistd.h>

/* default max bytes per packet to capture */
#define SNAP_LENGTH 1518

#define SIZE_ETHERNET 14

#define ETHER_ADDR_LEN 6

/* IP Header */
struct ipheader 
{
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

/* TCP header */
struct tcp_header 
{
    uint16_t source_port;         /* source port */
    uint16_t dest_port;           /* destination port */
    uint32_t seq_num;             /* sequence number */
    uint32_t ack_num;             /* acknowledgment number */
    uint8_t  data_offset;         /* data offset and reserved bits */
    uint8_t  flags;               /* flags */
    uint16_t window;              /* window size */
    uint16_t checksum;            /* checksum */
    uint16_t urgent_pointer;      /* urgent pointer */
};

/* UDP Header */
struct udpheader
{
  u_int16_t udp_sport;           /* source port */
  u_int16_t udp_dport;           /* destination port */
  u_int16_t udp_ulen;            /* udp length */
  u_int16_t udp_sum;             /* udp checksum */
};

/* ICMP Header  */
struct icmpheader 
{
  unsigned char icmp_type; // ICMP message type
  unsigned char icmp_code; // Error code
  unsigned short int icmp_chksum; //Checksum for ICMP Header and data
  unsigned short int icmpid;     //Used for identifying request
  unsigned short int icmpseq;    //Sequence number
};

void send_raw_ip_packet(struct ipheader* ip);

void spoff_udp();

void spoof_icmp();

void spoof_tcp();

unsigned short in_cksum (unsigned short *buf, int length);

unsigned short calculate_tcp_checksum(struct ipheader *ip);



void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int set_on = 1;

    /* Create a raw network socket */ 
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    /* Set socket option
    IPPROTO - IP protocol
    IP_HDRINCL - option that tells the kernel that the IP header is included in the data that is being sent
    set_on - set the IP_HDRINCL to 1
    */
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &set_on, sizeof(set_on));

    /* collect destination information of the packets */
    dest_info.sin_family = AF_INET; // IPV4 address
    dest_info.sin_addr = ip->iph_destip; // dest ip

    /* send the packet itself
    ip - a pointer to the IP header
    ntohs(ip->iph_len) - the length of the data to be sent
    (struct sockaddr *)&dest_info - a pointer to the sockaddr struct that contains the address info
     */
    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));

    close(sock); // close the socket
}

/*
The user need to choose which kind og protocol to use: ICMP, TCP or UDP
*/
int main(int argc, char *argv[])
{
    int choice; // user choice
    printf("Select a protocol number for spoffing packets: \n1.UDP \n2.ICMP \n3.TCP\n");
    scanf("%d", &choice);

    if(choice == 1) // UDP
    {
        spoff_udp();
    } 
    else if(choice == 2) // ICMP
    {
        spoof_icmp();
    } 
    else if(choice == 3) // TCP
    {
        spoof_tcp();
    }
    else 
    {
        printf("Invalid choice, execute the program again. \n");
        return(2);
    }

    return 0;
}

/* Spoffing UDP packets */
void spoff_udp()
{
    char buffer[1500];
    memset(buffer, 0, 1500); // set the buffer array with values of 0

    struct ipheader *ip = (struct ipheader *) buffer; // pointer of ipheader type to the start of the buffer
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader)); // pointer of udpheader type to the start of the buffer


    char *data = buffer + sizeof(struct ipheader) + sizeof(struct udpheader); // pointer to location in memory
    const char *message = "Hello from roy and yuval\n";
    int data_len = strlen(message); // length of message
    strncpy (data, message, data_len); // copy the message to the loacation pointed by the data pointer

    /* fill in the details of the udpheader struct */
    udp->udp_sport = htons(12345); // source port
    udp->udp_dport = htons(9090); // destination port
    udp->udp_ulen = htons(sizeof(struct udpheader) + data_len); // udp length
    udp->udp_sum =  0; // checksum set to 0 in order to ignore the calculation of it

    /* fill in the details of the ipheader struct */
    ip->iph_ver = 4; // IPV4
    ip->iph_ihl = 5; // internet header length
    ip->iph_ttl = 20; // Time to live
    ip->iph_sourceip.s_addr = inet_addr("1.1.1.1"); // source ip
    ip->iph_destip.s_addr = inet_addr("10.0.2.5"); // dest ip
    ip->iph_protocol = IPPROTO_UDP; // Protocol UDP
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct udpheader) + data_len); // total length of the ip header, icmp header and data in bytes 

    
    /* sending the spoffed packet*/
    send_raw_ip_packet(ip); // the method get the ipheader struct after the changing
}

/* Spoffing icmp packets */
void spoof_icmp()
{      
    char buffer[1500];
    memset(buffer, 0, 1500); // set the buffer array with values of 0


    struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader)); // pointer to an icmp header
    struct ipheader *ip = (struct ipheader *) buffer; // pointer of ipheader type to the start of the buffer


    icmp->icmp_type = 8; // set ICMP Type: 8 is request, 0 is reply.

    /* Calculate the checksum in order to make sure that the packet has not been tampered with during transmission */
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader)); 

    
    /* fill in the details of the ipheader struct */
    ip->iph_ver = 4; // IPV4
    ip->iph_ihl = 5; // internet header length
    ip->iph_ttl = 20; // Time to live
    ip->iph_sourceip.s_addr = inet_addr("1.1.1.1"); // source ip
    ip->iph_destip.s_addr = inet_addr("10.0.2.15"); // dest ip
    ip->iph_protocol = IPPROTO_ICMP; // protocol type
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader)); // total length of the ip header and icmp header in bytes 

    /* sending the spoffed packet*/
    send_raw_ip_packet(ip); // the method get the ipheader struct after the changing
}

/* Spoffing tcp packets */
void spoof_tcp()
{
    char buffer[1500];
    memset(buffer, 0, 1500); // set the buffer array with values of 0

    struct ipheader *ip = (struct ipheader *) buffer; // pointer of ipheader type to the start of the buffer
    struct tcp_header *tcp = (struct tcp_header *) (buffer + sizeof(struct ipheader)); // pointer of tcpheader type to the start of the buffer

    char *data = buffer + sizeof(struct ipheader) + sizeof(struct udpheader); // pointer to location in memory
    const char *message = "Hello from roy and yuval\n";
    int data_len = strlen(message); // length of message
    strncpy (data, message, data_len); // copy the message to the loacation pointed by the data pointer

    /* fill in the details of the tcpheader struct */
    tcp->source_port =htons(9898);
    tcp->dest_port =htons(80);
    tcp->ack_num = 0;
    tcp->seq_num = htons(2023);
    tcp->window = htons(1024);
    tcp->data_offset = 5 << 4;
    tcp->flags = 0x02;
    tcp->urgent_pointer = 0;
    tcp->checksum =  0; // checksum set to 0 in order to ignore the calculation of it


    /* fill in the details of the ipheader struct */
    ip->iph_ver = 4; // IPV4
    ip->iph_ihl = 5; // internet header length
    ip->iph_ttl = 20; // Time to live
    ip->iph_sourceip.s_addr = inet_addr("8.8.8.8"); // source ip
    ip->iph_destip.s_addr = inet_addr("10.0.2.15"); // dest ip
    ip->iph_protocol = IPPROTO_TCP; // protocol type
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct tcp_header) + data_len); // total length of the ip header, icmp header and data in bytes

    /* sending the spoffed packet*/
    send_raw_ip_packet(ip); // the method get the ipheader struct after the changing

}

unsigned short in_cksum (unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp=0;

    /*
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
    sum += (sum >> 16);                  // add carry
    return (unsigned short)(~sum);
}