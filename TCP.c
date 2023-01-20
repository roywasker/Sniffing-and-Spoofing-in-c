/* Psuedo TCP header */
struct pseudo_tcp
{
        unsigned saddr, daddr;
        unsigned char mbz;
        unsigned char ptcl;
        unsigned short tcpl;
        struct tcpheader tcp;
        char payload[PACKET_LEN];
};



unsigned short calculate_tcp_checksum(struct ipheader *ip)
{
   struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + sizeof(struct ipheader));

   int tcp_len = ntohs(ip->iph_len) - sizeof(struct ipheader);

   /* pseudo tcp header for the checksum computation */
   struct pseudo_tcp p_tcp;
   memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

   p_tcp.saddr  = ip->iph_sourceip.s_addr;
   p_tcp.daddr  = ip->iph_destip.s_addr;
   p_tcp.mbz    = 0;
   p_tcp.ptcl   = IPPROTO_TCP;
   p_tcp.tcpl   = htons(tcp_len);
   memcpy(&p_tcp.tcp, tcp, tcp_len);

   return  (unsigned short) in_cksum((unsigned short *)&p_tcp, tcp_len + 12);
}