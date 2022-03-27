# include "revert.h"
# include <string>
#include <iostream>
#include <fstream>
using namespace std;

class Http_identifier {
public:
    u_char* argument;
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    struct pkt_node* ppkt;
    void init(struct pcap_pkthdr* header,
        const u_char* pkt_data, struct pkt_node* ppkt);
    int ip_revert();
    int tcp_revert();
};

void Http_identifier::init(struct pcap_pkthdr* header,
    const u_char* pkt_data, struct pkt_node* ppkt) {
    this->header = header;
    this->pkt_data = pkt_data;
    this->ppkt = ppkt;
}

int Http_identifier::ip_revert() {
    struct ip_header* ip_protocol;
    int res = 0;
    int tcp_header_length;

    //packet_header是winpcap加上的捕获信息，真正的ip_header还是在packet_content里
    ip_protocol = (struct ip_header*)(pkt_data + 14);//length of ethernet header

    ppkt->saddr = ip_protocol->saddr;
    ppkt->daddr = ip_protocol->daddr;

    return ip_protocol->proto;
}

int Http_identifier::tcp_revert() {
    struct tcp_header* tcp_protocol;
    u_char flags;
    int res;

    //跳过mac协议和ip协议 
    tcp_protocol = (struct tcp_header*)(pkt_data + 14 + 20);
    ppkt->sport = ntohs(tcp_protocol->sport);
    ppkt->dport = ntohs(tcp_protocol->dport);

    ppkt->tcp_header_length = tcp_protocol->offset * 4;
    ppkt->sequence = ntohl(tcp_protocol->sequence);
    printf("sequence: %d\n", ppkt->sequence);
    flags = tcp_protocol->flags;

    if (flags & 0x08)
    {
        cout<<"PSH"<<endl;
        printf("dport: %d, sport: %d\n", ppkt->dport, ppkt->sport);
        return 0;
    }
    if (flags & 0x10) printf("ACK");
    if (flags & 0x02) printf("SYN");
    if (flags & 0x20) printf("URG");
    if (flags & 0x01) printf("FIN");
    if (flags & 0x04) printf("RST");
    printf("\n");

    printf("dport: %d, sport: %d\n", ppkt->dport, ppkt->sport);
    return 0;
}

class Http_reverter {
public:
    u_char* argument;
    struct pcap_pkthdr* header;
    struct pkt_node* ppkt;
    const u_char* pkt_data;
    char* save_path;
    void init(struct pcap_pkthdr* header,
        const u_char* pkt_data, 
        struct pkt_node* ppkt, char* save_path);

};

void Http_reverter::init(struct pcap_pkthdr* header,
    const u_char* pkt_data,
    struct pkt_node* ppkt, char* save_path) {
    this->pkt_data = pkt_data;
    this->header = header;
    this->ppkt = ppkt;
    this->save_path = save_path;
}

class Request_reverter : public Http_reverter {
    int head_save();
    int http_head_parse();
    char method[10];
    char URL[50];
    char http[10];
};

class Respond_reverter : public Http_reverter {
public:
    struct key_word key;
    char* content;
    int http_head_start;
    int http_body_start;
    int head_save();//返回值0有http头,1 没有http头，-1读写操作出错
    int http_head_parse();//返回0状态正确，1状态出错，-1读写操作出错
    int http_handling(int& mark, struct key_word key_now);
    int match_head(char* s);
    int match_type(char* s);
    int save_image(int mark);
    int save_application(int mark);
    int handle_txt(int mark);
    int handle_chunked();
};

int Respond_reverter::head_save() {
    int i;
    key.seq = ppkt->sequence;
    http_head_start = 14 + 20 + ppkt->tcp_header_length;
    if (pkt_data[http_head_start] == 'H' && pkt_data[http_head_start + 1] == 'T'
        && pkt_data[http_head_start + 2] == 'T' && pkt_data[http_head_start + 3] == 'P')
    {
        /* 将协议头部写入文件后按单词读取 */
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

        ofstream outfile;
        try {
            outfile.open(save_path);
        }
        catch (std::ios_base::failure& e) {
            std::cerr << e.what() << endl;
            return -1;
        }
        outfile << content << endl;
        outfile.close();
        return 0;
    }
    else {
        return 1;
    }    
}

int Respond_reverter::http_head_parse() {
    //初始化key中的值为0，是0表示http头部没有出现改值
    strcpy(key.Content_Encoding, "\0");
    strcpy(key.Content_Length, "\0");
    strcpy(key.Content_Type, "\0");
    char http_version[10];
    char status[10];
    char modifier[10];
    ifstream infile;
    try {
        infile.open(save_path);
    }
    catch (std::ios_base::failure& e) {
        std::cerr << e.what() << endl;
        return -1;
    }
    infile >> http_version;
    infile >> status;
    infile >> modifier;
    if (strcmp(status, "200") != 0)
    {
        cout << "The respond is not correct!"<<endl;
        cout << "The false status is " << status
            << " " << modifier << endl;
        return 1;
    }
    char  tmp1[50], tmp2[50];
    while (infile >> tmp1) {
        int type = match_head(tmp1);
        if (type != 0 && type != 4) infile >> tmp2;
        switch (type) {
        case 1: strcpy(key.Content_Encoding, tmp2);break;
        case 2: strcpy(key.Content_Length, tmp2);break;
        case 3: strcpy(key.Content_Type, tmp2);break;
        case 4: key.if_chunked = 1;break;
        }
    }
    infile.close();
    return 0;
}

int Respond_reverter::match_head(char* s) {
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

int Respond_reverter::http_handling(int& mark
    ,struct key_word key_now) {
    int start_seq = key_now.seq;
    if (ppkt->sequence - start_seq <atoi(key_now.Content_Length)){
        int res = 0;
        if (key.Content_Type) {
            res = match_type(key_now.Content_Type);
            switch (res) {
            case 1: save_image(mark);break;
            case 2: save_application(mark);break;
            case 3: handle_txt(mark);break;
            default: cout << "This type can not be handled" << endl;return -1;
            }
        }        
    }
    else mark = 0;
    return 0;
}

int Respond_reverter::match_type(char* s) {
    if (strstr(s, "image"))
        return 1;
    else if (strstr(s, "application"))
        return 2;
    else if (strstr(s, "text"))
        return 3;
    else
        return 0;
}

int Respond_reverter::save_image(int mark) {
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

int Respond_reverter::save_application(int mark) {
    //mark=0表示是数据包的开头，有http头部
    if (!mark) {
        if (!strcmp(key.Content_Encoding, "\0"))
            cout << "The application is not encoded." << endl;
        else
            cout << "The application is encoded by "
            << key.Content_Encoding << endl;
        ofstream outfile;
        try {
            outfile.open(save_path,ios::app);
        }
        catch (std::ios_base::failure& e) {
            std::cerr << e.what() << endl;
            return -1;
        }
        outfile << "Date" << __DATE__ << endl;
        outfile.close();
    }    
    if (key.if_chunked) {
        handle_chunked();
    }
    else {
        ofstream outfile;
        try {
            outfile.open(save_path,ios::app);
        }
        catch (std::ios_base::failure& e) {
            std::cerr << e.what() << endl;
            return -1;
        }
        outfile << &pkt_data[http_body_start] << endl;
        outfile.close();
    }
    return 0;
}

int Respond_reverter::handle_txt(int mark) {
    return 0;
}

int Respond_reverter::handle_chunked() {
    return 0;
}

int packet_revert()
{
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
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
    ) != 0){
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
    )) == NULL){
        fprintf(stderr, "\nUnable to open the file %s.\n", source);
        return -1;
    }

    int mark = 0;
    int start_seq = 0;
    struct key_word key_now;
    while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
    {
        struct pkt_node pkt;
        struct pkt_node* ppkt;
        ppkt = &pkt;
        int is_HTTP = propotoral_identify(header, pkt_data, ppkt);
        if (is_HTTP == 0) {
            ;
        }
        else if (is_HTTP == 1) {
            if (ppkt->dport == 80) {

            }
            else {
                int res=0;
                Respond_reverter reverter;
                char* save_path = "test2.txt";
                reverter.init(header, pkt_data, ppkt, save_path);
                res=reverter.head_save();
                //有http头，表示是新数据的开头
                //设置mark，start_seq, key和length
                if (res == 0) {
                    res=reverter.http_head_parse();
                    if (res == 1) continue;
                    //表示状态不正确，进行下一轮
                    if (mark) {
                        cout << "sequence is error" << endl;
                        //出现乱序，上一个数据包的数据还未完整接收
                    }
                    start_seq = ppkt->sequence;
                    key_now = reverter.key;
                    reverter.http_handling(mark, key_now);
                    mark = 1;
                }
                else if (res == 1) {
                    reverter.http_body_start = reverter.http_head_start;
                    reverter.http_handling(mark, key_now);
                }
                else
                    return -1;
            }            
        }
    }
        
    if (res == -1){
        printf("Error reading the packets: %s\n", pcap_geterr(fp));
        return -1;
    }

    return 0;       
}

int propotoral_identify(struct pcap_pkthdr* header,
    const u_char* pkt_data, struct pkt_node* ppkt) {
    int res = -1;
    Http_identifier identifier;
    identifier.init(header, pkt_data, ppkt);
    int ip_proto = 0;
    ip_proto = identifier.ip_revert();
    if (ip_proto == 6) identifier.tcp_revert();
    else cout << "is not HTTP" << endl;
    if (ppkt->dport == 80)
    {
        cout << "request HTTP" << endl;
        res = 0;
    }
    else if (ppkt->sport == 80)
    {
        cout << "respond HTTP" << endl;
        res = 1;
    }
    else cout << "is not HTTP" << endl;
    cout << endl;
    return res;
}



