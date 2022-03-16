# include "revert.h"

int propotoral_revert()
{
    int res;
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    res=read_file(header, pkt_data);
    return res;
}

int read_file(struct pcap_pkthdr*& header,
    const u_char*& pkt_data)
{
    time_t local_tv_sec;
    pcap_t* fp;
    pcap_dumper_t* dumpfile;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* path = "test.txt";
    char source[PCAP_BUF_SIZE];
    int res = 0;
    int i = 0;

    /* 读取转存的数据包 */
    /* Create the source string according to the new WinPcap syntax */
    if (pcap_createsrcstr(source,         // variable that will keep the source string
        PCAP_SRC_FILE,  // we want to open a file
        NULL,           // remote host
        NULL,           // port on the remote host
        path,        // name of the file we want to open
        errbuf          // error buffer
    ) != 0)
    {
        fprintf(stderr, "\nError creating a source string\n");
        return -1;
    }

    /* Open the capture file */
    if ((fp = pcap_open(source,         // name of the device
        65536,          // portion of the packet to capture
                        // 65536 guarantees that the whole packet will be captured on all the link layers
        PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode 混合模式
        1000,              // read timeout
        NULL,              // authentication on the remote machine
        errbuf         // error buffer
    )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the file %s.\n", source);
        return -1;
    }


    while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
    {
        /* 调试代码
        ip_header* ih;
        u_int ip_len;
        //retireve the position of the ip header 
        ih = (ip_header*)(pkt_data +
            14); //length of ethernet header

        // retireve the position of the udp header 
        ip_len = (ih->ver_ihl & 0xf) * 4;
        printf("\n%.2x\n", ip_len);

        printf("\n%.2x\n", ih->proto);

        printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

        for (i = 1; (i < header->caplen + 1); i++)
        {
            printf("%.2x ", pkt_data[i - 1]);
            if ((i % LINE_LEN) == 0) printf("\n");
        }

        printf("\n\n");
        */
        res = ip_revert(NULL, header, pkt_data);
    }


    if (res == -1)
    {
        printf("Error reading the packets: %s\n", pcap_geterr(fp));
        return -1;
    }

    return 0;       
}

int ip_revert(
    u_char* argument,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data
) {
    struct ip_header* ip_protocol;
    int res = 0;
    int i;
    int tcp_header_length;
    /*
    u_int header_length;
    u_char tos;
    u_short checksum;

    ip_address saddr;
    ip_address daddr;
    u_char ttl;
    u_short tlen;
    u_short identification;
    u_short offset;
    */

    //packet_header是winpcap加上的捕获信息，真正的ip_header还是在packet_content里
    ip_protocol = (struct ip_header*)(pkt_data + 14);//length of ethernet header
    /*
    header_length = ip_protocol->header_length * 4;
    checksum = ntohs(ip_protocol->checksum);
    tos = ip_protocol->tos;
    offset = ntohs(ip_protocol->offset);

    saddr = ip_protocol->saddr;
    daddr = ip_protocol->daddr;
    ttl = ip_protocol->ttl;
    identification = ip_protocol->identification;
    tlen = ip_protocol->tlen;
    offset = ip_protocol->offset;
    //printf("IP: %d%d%c%d%d%d\n", saddr, daddr, ttl, identification, tlen, offset);
    //fprintf(fp, "%d%d%c%d%d%d", saddr, daddr, ttl, identification, tlen, offset);
    */
    //printf("%d\n", ip_protocol->proto);
    if (ip_protocol->proto==6) {
        res=tcp_revert(argument, header, pkt_data, tcp_header_length);
        return res;
    }
    return 0;
}

int tcp_revert(
    u_char* argument,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data,
    int& tcp_header_length
) {
    struct tcp_header* tcp_protocol;
    u_short sport;
    u_short dport;
    int header_length;
    u_short windows;
    u_short urgent_pointer;
    u_int sequence;
    u_int acknowledgement;
    u_short checksum;
    u_char flags;
    int res;
  
    
    tcp_protocol = (struct tcp_header*)(pkt_data + 14 + 20);//跳过mac协议和ip协议 
    sport = ntohs(tcp_protocol->sport);
    dport = ntohs(tcp_protocol->dport);
    header_length = tcp_protocol->offset * 4;
    sequence = ntohl(tcp_protocol->sequence);
    acknowledgement = ntohl(tcp_protocol->ack);
    windows = ntohs(tcp_protocol->windows);
    urgent_pointer = ntohs(tcp_protocol->urgent_pointer);
    flags = tcp_protocol->flags;
    checksum = ntohs(tcp_protocol->checksum);
    tcp_header_length = header_length;
    printf("\nTCP:%d\n", header_length);
    //printf("TCP: %d0%d%d%c%d\n", header_length, sport, dport, flags, windows);
    //fprintf(fp, "%d0%d%d%c%d", header_length, sport, dport, flags, windows);
    if (flags & 0x08)
    {
        printf("PSH"); 
        printf("dport: %d, sport: %d\n", dport, sport);
        return 0;
    }
    if (flags & 0x10) printf("ACK");
    if (flags & 0x02) printf("SYN");
    if (flags & 0x20) printf("URG");
    if (flags & 0x01) printf("FIN");
    if (flags & 0x04) printf("RST");
    printf("\n");

    printf("dport: %d, sport: %d\n", dport, sport);
    if (dport == 80)
    {
        res=request_revert(argument, header, pkt_data, tcp_header_length);
        return res;
    }
    else if(sport == 80)
    {
        res = respond_revert(argument, header, pkt_data, tcp_header_length);
    }
    return 0;
    
}

int request_revert(
    u_char* argument,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data,
    int tcp_header_length
) {
    int i;
    for (i = (14 + 20 + tcp_header_length); i < header->caplen ; i++)
    {
        printf("%c", pkt_data[i]);
        //if ((i % LINE_LEN) == 0) printf("\n");
    }
    return 0;
}

int respond_revert(
    u_char* argument,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data,
    int tcp_header_length
) {
    int i;
    for (i = (14 + 20 + tcp_header_length); i < header->caplen; i++)
    {
        printf("%c", pkt_data[i]);
        //if ((i % LINE_LEN) == 0) printf("\n");
    }
    return 0;
}
