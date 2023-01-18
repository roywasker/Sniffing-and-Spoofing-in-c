#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

/* 
Compile: gcc -o Sniffer Sniffer.c -lpcap  
Execute: sudo ./Sniffer
*/


#define SIZE_ETHERNET 14
#define SNAP_LENGTH 1518

FILE *fp_txt; // a pointer to the text file itself



/*  this method is called when a packet is received on the network.
    *args is a pointer to user supplied data.
    *header is a pointer to a pcap_pkthdr struct which contains the packet timestamp, length and the 
    amount of data available in the capture.
    *packet is a pointer to the raw packet data.
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet); 

/* Ethernet header */
struct sniff_ethernet
{
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip 
{
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp 
{
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) > 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

/* struct to extract flags, status code and cache control */
struct calculatorPacket
{
    uint32_t unixtime;
    uint16_t length;

    union 
    {
        uint16_t flags;
        uint16_t :3, c_flag:1, s_flag:1,
        t_flag:1, status:10;
    };
    
    uint16_t cache;
    // uint16_t__;
};


int main(int argc, char *argv[]) 
{
    pcap_t *handle; // a pointer to pcap_t struct, used to handle with packet capture operations
    char *devname; // name of the network interface device
    char error_buffer[PCAP_ERRBUF_SIZE]; // hold an error massage in the libpacp library if there is one, size is defined in pcap.h
    struct bpf_program bpf; // a pointer to a struct that contains information about specific BPF program
    char filter[] = "tcp"; // TCP filter type
    bpf_u_int32 net; // the ip of our sniffing device
    pcap_if_t *alldevices; // pointer to a struct that contains linked list of all the network devices that been found


    /*
    pcap_findalldevs find a list of all available network interfaces
    */
    if(pcap_findalldevs(&alldevices, error_buffer) == -1) // cheking if function managed to find network devices
    {
        printf("Error in pcap_findalldevs: %s\n", error_buffer);
        return(2);
    }

    char temp[20]; // assuming there isn't device name length larger than 20
    for (pcap_if_t *d = alldevices; d != NULL; d = d->next) // print the list of the networks names
    {
        printf("%s\n", d->name);
    }
    printf("Enter the device to sniff on: ");
    scanf("%s", temp); // temp = user input
    devname = temp;


    if(devname == NULL) // cheking if the function managed to find a network device
    {
        printf("Error in finding a network device: %s\n", error_buffer);
        return (2);
    }
    printf("Network device is found: %s\n", devname); // printing the device name if found one


    /*
    pcap_open_live method obtain a packet capture handle to look at packets on the network
    devname - the network device to open
    SNAP_LENGTH - specifies the snapshot length to be set on the handle
    1 - non-zero in order to turn on promiscuous mode
    1000 - the packet buffer timeout in milliseconds
    error_buffer - the error message if there is any
    */
    handle = pcap_open_live(devname, SNAP_LENGTH, 1, 1000, error_buffer);
    if(handle == NULL) // checking if function managed to open the network device
    {
        printf("Couldn't open %s network device : %s\n", devname, error_buffer);
        pcap_freealldevs(alldevices);
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
    pcap_freealldevs(alldevices); // list of devices is freed

    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int counter_pack = 1; // counting the packets

    const struct sniff_ethernet *ethernet; // the ETHERNET header
    const struct sniff_ip *ip; // the IP header
    const struct sniff_tcp *tcp; // the TCP header
    const char *payload; // the packet Payload
    struct calculatorPacket calc_packets; // the calculator header


    u_int ip_size; // length of the IP header
    u_int tcp_size; // length of the tcp header
    int payload_size; // size of the payload

    ip_size = IP_HL(ip)*4; // the length of the IP header in bytes
    tcp_size = TH_OFF(tcp)*4; // the length of the TCP header in bytes
    ethernet = (struct sniff_ethernet*) (packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET); // the location of the variable in bytes
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + ip_size); // the location of the variable in bytes
    payload = (u_char*)(packet + SIZE_ETHERNET + tcp_size + ip_size); // the location of the variable in bytes
    payload_size = ntohs(ip->ip_len) - (ip_size + tcp_size); // TCP payload segment size

    char filename[] = "/home/yuval/Documents/Reshatot/EX5/208720383_208957084.txt"; // name of the text file to write the TCP packets into


    // source IP
    char source_ip[INET_ADDRSTRLEN]; // INET_ADDRSTRLEN is the max length of an IPV4 address as a string
    inet_ntop(AF_INET, inet_ntoa(ip->ip_src), source_ip, INET_ADDRSTRLEN); // converts a binary ip address into a string

    // dest IP
    char dest_ip[INET_ADDRSTRLEN]; // INET_ADDRSTRLEN is the max length of an IPV4 address as a string
    inet_ntop(AF_INET, inet_ntoa(ip->ip_dst), dest_ip, INET_ADDRSTRLEN); // converts a binary ip address into a string

    // source port
    uint16_t src_port = ntohs(tcp->th_sport);

    // dest port
    uint16_t dst_port = ntohs(tcp->th_dport);

    // timestamp
    time_t timestamp = header->ts.tv_sec;

    // total lentgh of the packet
    bpf_u_int32 length = header->len;

    // cache_flag
    uint16_t cache_flag = calc_packets.flags & 0x0008;

    // steps_flag
    uint16_t steps_flag = calc_packets.flags & 0x0004;

    // type_flag
    uint16_t type_flag = calc_packets.flags & 0x0002;

    // status_code
    uint16_t status_code = calc_packets.flags & 0x03FC;

    // cache_control
    uint16_t cache_control = calc_packets.cache;



    /*
    open the text file that called "208720383_208957084"
    */
    fp_txt = fopen(filename, "a");
    if(fp_txt == NULL) 	// check if the file did open successfuly
    {
        printf("Failed to open the file: %s", filename);
    }



    // writing the TCP packet into the text file 
    fprintf(fp_txt, "Packet number: %d\n", counter_pack); // write the packet number
    counter_pack++; // raise the counter by one
    fprintf(fp_txt, "Source ip: %s\n", source_ip); // write source ip
    fprintf(fp_txt, "Destination ip: %s\n", dest_ip); // write dest ip
    fprintf(fp_txt, "Source port: %u\n", src_port); // write source port
    fprintf(fp_txt, "Destination port: %u\n", dst_port); // write dest port
    fprintf(fp_txt, "Timestamp: %ld\n", timestamp); // write timestamp
    fprintf(fp_txt, "Total length: %u\n", length); // write total length
    fprintf(fp_txt, "Cache_flag: %u\n", cache_flag); // write Cahce flag        <--------------*************complete**************
    fprintf(fp_txt, "Steps_flag: %u\n", steps_flag); // write steps flag        <--------------*************complete**************
    fprintf(fp_txt, "Type_flag: %u\n", type_flag); // write type flag          <--------------*************complete**************
    fprintf(fp_txt, "Status_code: %u\n", status_code); // write status code      <--------------*************complete**************
    fprintf(fp_txt, "Cache control: %u\n", cache_control); // write cache control 
    fprintf(fp_txt, "Data: "); // write data
    for (int i = 0; i < payload_size; i++)
    {
        fprintf(fp_txt, "%02x", payload[i]);
    }
    fprintf(fp_txt, "\n\n");

    printf("Packet number %d captured\n", counter_pack-1);

    fclose(fp_txt); // close the text file
}
