#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

FILE *fp_txt; // a pointer to the text file itself
int counter_pack = 0 ;

/* struct to extract flags, status code and cache control */
struct appheader{
    uint32_t unixtime;
    unsigned int length :16;
    unsigned int save   :3;
    unsigned int c_flag :1;
    unsigned int s_flag :1;
    unsigned int t_flag :1;
    unsigned int status :10;
    uint16_t cache;
    unsigned int repod  :16;
};


int main(int argc, char *argv[])
{
    pcap_t *handle; // a pointer to pcap_t struct, used to handle with packet capture operations
    char *devname = "lo"; // name of the network interface device
    char error_buffer[PCAP_ERRBUF_SIZE]; // hold an error massage in the libpacp library if there is one, size is defined in pcap.h
    struct bpf_program bpf; // a pointer to a struct that contains information about specific BPF program
    char filter[] = "tcp"; // TCP filter type
    bpf_u_int32 net; // the ip of our sniffing device

    handle = pcap_open_live(devname, BUFSIZ , 1, 1000, error_buffer);
    if(handle == NULL) // checking if function managed to open the network device
    {
        printf("Couldn't open %s network device : %s\n", devname, error_buffer);
        return (2);
    }
    printf("The network device - %s is opened...\n", devname);

    /*
    pcap_compile method create a filter in order to select only the packets of interest, like TCP
    0 - specifies to not optimize the filter - typically set to 0
    PCAP_NETMASK_UNKNOWN/net - the netmask for the capture device
    */
    if(pcap_compile(handle, &bpf, filter, 0, net) == -1) // checking if function managed to compile the filter
    {
        printf("Compiling went wrong, couldn't compile filter %s: %s\n", filter, pcap_geterr(handle));
        // pcap_geterr returns a pointer to the last error massage stored in the error_buffer //
        return (2);
    }
    printf("The filter compiled...\n");

    /*
    pcap_setfilter method apply the filter to the capture handle
    */
    if(pcap_setfilter(handle, &bpf) == -1) // checking if function managed to install the filter
    {
        printf("Innstallation of the %s filter failed: %s\n", filter, pcap_geterr(handle));
        return (2);
    }
    printf("The filter installed...\n");

    /*
    capture packets from a network interface and process them in a loop.
    "-1" - The number of packets to capture, -1 symbolize capture indefinitely
    got_packet - a callback function, which is called for each packet that is captured.
    */

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&bpf);
    pcap_close(handle); // close the handle

    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    struct iphdr *iphdr = (struct iphdr*) (packet + sizeof(struct ethhdr));

    unsigned short iplen =iphdr->ihl*4;

    struct tcphdr *tcphdr =(struct tcphdr* ) (packet +iplen + sizeof(struct ethhdr));

    unsigned short tcplen = tcphdr->doff*4;

    struct appheader *appheader =(struct appheader*) (packet + iplen + tcplen + sizeof(struct ethhdr));

    char filename[] = "208720383_208957084.txt"; // name of the text file to write the TCP packets into

    /*
   open the text file that called "208720383_208957084"
   */
    fp_txt = fopen(filename, "a");
    if(fp_txt == NULL) 	// check if the file did open successfuly
    {
        printf("Failed to open the file: %s", filename);
    }

    struct sockaddr_in source,dest;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iphdr->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iphdr->daddr;

    // writing the TCP packet into the text file
    fprintf(fp_txt, "Packet number: %d\n", counter_pack); // write the packet number
    counter_pack++;

    printf("Packet number %d captured\n", counter_pack);

    fprintf(fp_txt,"Source ip: %s\n", inet_ntoa(source.sin_addr));
    fprintf(fp_txt,"Destination ip: %s\n", inet_ntoa(dest.sin_addr)); // write dest ip
    fprintf(fp_txt,"Source port %u \n",ntohs(tcphdr->source));
    fprintf(fp_txt,"Destination port %u \n",ntohs(tcphdr->dest));
    fprintf(fp_txt,"Timestamp  : %s",ctime((const time_t*) &header->ts.tv_sec));
    fprintf(fp_txt,"Total length: %u\n",appheader->length); // write total length
    fprintf(fp_txt,"Cache_flag: %u\n",appheader->c_flag); // write Cahce flag
    fprintf(fp_txt,"Steps_flag: %u\n",appheader->s_flag); // write steps flag
    fprintf(fp_txt,"Type_flag: %u\n",appheader->t_flag); // write type flag
    fprintf(fp_txt,"Status_code: %u\n", appheader->status); // write status code
    fprintf(fp_txt,"Cache control: %u\n",appheader->cache);
    fprintf(fp_txt, "Data: "); // write data

    packet =(packet + iplen + tcplen + sizeof(struct ethhdr) + sizeof(struct appheader));

    int bytes = ntohs(iphdr->ihl)-(sizeof(struct iphdr) + sizeof(struct tcphdr));

    for ( int i = 0; i < bytes; i++ )
    {
        if ( !(i & 15) ) fprintf(fp_txt,"\n%04X:  ", i);
        fprintf(fp_txt,"%02X ", packet[i]);
    }

    fprintf(fp_txt, "\n\n");

    fclose(fp_txt); // close the text file
}