#include <pcap.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>

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

/* ICMP Header  */
struct icmpheader
{
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmpid;     //Used for identifying request
    unsigned short int icmpseq;    //Sequence number
};

unsigned short in_cksum (unsigned short *buf, int length);

void send_raw_ip_packet(struct ipheader* ip);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


int main(){

    pcap_t *handle; // a pointer to pcap_t struct, used to handle with packet capture operations
    char *devname = "enp0s3"; // name of the network interface device
    char error_buffer[PCAP_ERRBUF_SIZE]; // hold an error massage in the libpacp library if there is one, size is defined in pcap.h
    struct bpf_program bpf; // a pointer to a struct that contains information about specific BPF program
    char filter[] = "icmp"; // TCP filter type
    bpf_u_int32 net; // the ip of our sniffing device

    handle = pcap_open_live(devname, BUFSIZ , 1, 1000, error_buffer);
    if(handle == NULL) // checking if function managed to open the network device
    {
        printf("Couldn't open %s network device : %s\n", devname, error_buffer);
        return (2);
    }
    printf("The network device - %s is opened...\n", devname);

    if(pcap_compile(handle, &bpf, filter, 0, net) == -1) // checking if function managed to compile the filter
    {
        printf("Compiling went wrong, couldn't compile filter %s: %s\n", filter, pcap_geterr(handle));
        return (2);
    }
    printf("The filter compiled...\n");

    if(pcap_setfilter(handle, &bpf) == -1) // checking if function managed to install the filter
    {
        printf("Innstallation of the %s filter failed: %s\n", filter, pcap_geterr(handle));
        return (2);
    }
    printf("The filter installed...\n");

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&bpf);
    pcap_close(handle); // close the handle

    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    struct ipheader *iphdr = (struct ipheader*) (packet + sizeof(struct ethhdr));

    unsigned short iplen = iphdr->iph_ihl*4;

    struct icmpheader *recvicmp = (struct icmpheader*) (packet + sizeof(struct ethhdr) + iplen );

    if (recvicmp->icmp_type == 8) { // 8 is icmp request

        printf("sniff icmp request packet form %s ",inet_ntoa(iphdr->iph_sourceip));
        printf("to %s \n",inet_ntoa(iphdr->iph_destip));
        printf("spoff icmp reply packet form %s ",inet_ntoa(iphdr->iph_destip));
        printf("to %s \n",inet_ntoa(iphdr->iph_sourceip));

        char buffer[1500];
        memset(buffer, 0, 1500); // set the buffer array with values of 0
        memcpy((char *)buffer, iphdr, ntohs(iphdr->iph_len));
        struct icmpheader *icmp = (struct icmpheader *) (buffer + sizeof(struct ipheader)); // pointer to an icmp header
        struct ipheader *ip = (struct ipheader *) buffer; // pointer of ipheader type to the start of the buffer

        icmp->icmp_type = 0; // set ICMP Type: 8 is request, 0 is reply.

        /* Calculate the checksum in order to make sure that the packet has not been tampered with during transmission */
        icmp->icmp_chksum = 0;
        icmp->icmp_chksum = in_cksum((unsigned short *) icmp, sizeof(struct icmpheader));


        /* fill in the details of the ipheader struct */
        ip->iph_ver = 4; // IPV4
        ip->iph_ihl = 5; // internet header length
        ip->iph_ttl = 20; // Time to live
        ip->iph_sourceip.s_addr = inet_addr(inet_ntoa(iphdr->iph_destip));; // source ip
        ip->iph_destip.s_addr = inet_addr(inet_ntoa(iphdr->iph_sourceip));; // dest ip
        ip->iph_protocol = IPPROTO_ICMP; // protocol type
        ip->iph_len = htons(sizeof(struct ipheader) +sizeof(struct icmpheader)); // total length of the ip header and icmp header in bytes

        /* sending the spoffed packet*/
        send_raw_ip_packet(ip); // the method get the ipheader struct after the changing
    }
}


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
    int bytes = sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    if (bytes > 0){
        printf("spoffer packet send successfully \n\n");
    }
    close(sock); // close the socket
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