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
    char method[10];
    char URL[50];
    char http[10];
    int http_start = 14 + 20 + tcp_header_length;
    for (i = http_start; i < header->caplen ; i++)
    {
        printf("%c", pkt_data[i]); 
        /*
        int j = http_start;
        for (int k = 0;pkt_data[j] != ' ';j++, k++){
            method[k] = pkt_data[j];
        }
        for (int k = 0;pkt_data[j] != ' ';j++, k++) {
            URL[k] = pkt_data[j];
        }
        */
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
    struct key_word key;//要初始化为0
    char* content;
    int http_head_start;
    int http_body_start;
    //Trie t;
    http_head_start = 14 + 20 + tcp_header_length;
    if (pkt_data[http_head_start] == 'H' && pkt_data[http_head_start + 1] == 'T'
        && pkt_data[http_head_start + 2] == 'T' && pkt_data[http_head_start + 3] == 'P')
    {
        /* 将协议头部写入文件后按单词读取 */
        //u_char不能直接写入文件，所以要用content转换成char之后再写入
        content = (char*)malloc(header->caplen * sizeof(char));
        for (i = http_head_start; i < header->caplen; i++)
        {
            //两个回车表示头部结束
            if (pkt_data[i] == '\r' && pkt_data[i + 1] == '\n'
                && pkt_data[i + 2] == '\r' && pkt_data[i + 3] == '\n')
                break;
            printf("%c", pkt_data[i]);
            content[i - http_head_start] = pkt_data[i];
        }
        http_body_start = i + 4;
        content[i - http_head_start] = '\0';
        FILE* temp;
        temp = fopen("test2.txt", "w+");
        fputs(content, temp);
        fclose(temp);
        http_head_parse(key);
        http_handling(key, pkt_data, http_body_start);
    }   
    return 0;
}

int match_head(char* s) {
    const struct key_mode mode;
    if (strcmp(s, mode.encoding) == 0)
        return 1;
    else if (strcmp(s, mode.length) == 0)
        return 2;
    else if (strcmp(s, mode.type) == 0)
        return 3;
    else if (strcmp(s, mode.chunked) == 0)
        return 4;
    else
        return 0;
}

int match_type(char* s) {
    if (strstr(s, "image"))
        return 1;
    else if (strstr(s, "application"))
        return 2;
    else if (strstr(s, "text"))
        return 3;
    else
        return 0;
}


int http_head_parse(struct key_word& key) {
    char http_version[50];
    char status[50];
    char modifier[50];
    FILE* fp;
    fp = fopen("test2.txt", "r");
    fscanf(fp, "%s %s %s", http_version, status, modifier);
    while (1) {
        char  tmp1[50], tmp2[50];
        fscanf(fp, "%s", tmp1);
        int type = match_head(tmp1);
        //t.find(head_name, type);
        if (type != 0 && type != 4) fscanf(fp, "%s", tmp2);
        switch (type) {
        case 1: strcpy(key.Content_Encoding, tmp2);break;
        case 2: strcpy(key.Content_Length, tmp2);break;
        case 3: strcpy(key.Content_Type, tmp2);break;
        case 4: key.if_chunked = 1;break;
        }
        if (feof(fp)) break;
    }
    fclose(fp);
    return 0;
}

int http_handling(struct key_word key, const u_char* pkt_data,
int body_start) {
    int res = 0;
    if (key.Content_Type) {
        res = match_type(key.Content_Type);
        switch (res) {
        case 1: save_image(key, pkt_data, body_start);break;
        case 2: save_application(key, pkt_data, body_start);break;
        case 3: handle_txt(key, pkt_data, body_start);break;
        }
    }
    return 0;
}

void handle_chunked() {

}

int save_image(struct key_word key, const u_char* pkt_data,
    int body_start) {
    if (key.Content_Encoding)
        printf("The image is encoded by %s\n", key.Content_Encoding);
    else
        printf("The image is not encoded.\n");
    printf("This image will be stored in .\n");
    if (key.if_chunked) {
        printf("chunked");
        handle_chunked();
    }
    else {
        //保存图片的后缀名即为图片的格式
        //内容格式image/图片格式，跳过"image/"
        char* picture_type = key.Content_Type + 6;
        printf("%s", picture_type);
    }
    FILE* fp;
    fp = fopen("picture.txt", "w");
    fclose(fp);
    return 0;
}

int save_application(struct key_word key, const u_char* pkt_data,
    int body_start) {
    char* data = (char*)pkt_data;
    if (key.Content_Encoding)
        printf("The application is encoded by %s", key.Content_Encoding);
    else
        printf("The application is not encoded.");
    if (key.if_chunked) {
        handle_chunked();
    }
    else {
        FILE* fp;
        fp = fopen("application.txt", "a+");
        fprintf(fp, "Date: %s", __DATE__);
        fputs(data + body_start, fp);
    }
    return 0;
}

int handle_txt(struct key_word key, const u_char* pkt_data,
    int body_start) {
    return 0;
}
/*
class Trie {
public:
    int nex[50][26], cnt;
    bool exist[50];  // 该结点结尾的字符串是否存在

    void insert(char* s) {  // 插入字符串
        int p = 0;
        int l = strlen(s);
        for (int i = 0; i < l; i++) {
            if ('A' <= s[i] <= 'Z')
                s[i] = s[i] + 32;//统一大小写，不区分查找
            int c = s[i] - 'a';
            if (!nex[p][c]) nex[p][c] = ++cnt;  // 如果没有，就添加结点
            p = nex[p][c];
        }
        exist[p] = 1;
    }

    bool find(char* s, int& type) {  // 查找字符串
        int p = 0;
        int l = strlen(s);
        for (int i = 0; i < l; i++) {
            if ('A' <= s[i] <= 'Z')
                s[i] = s[i] + 32;//统一大小写，不区分查找
            int c = s[i] - 'a';
            if (!nex[p][c]) return 0;
            p = nex[p][c];
        }
        type = p;
        return exist[p];
    }
};

void create_trie(Trie t) {
    t.insert("Content-T");
    t.insert("Content-Le");
    t.insert("Content-E");
    t.insert("chunked");
}
*/