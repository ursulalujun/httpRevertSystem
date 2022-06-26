# include "revert.h"
# include <string>
#include <iostream>
#include <fstream>
using namespace std;

//重载==操作符，比较ip_address
bool ip_address::operator == (const ip_address& rhs)
{
    return ((byte1 == rhs.byte1) && (byte2 == rhs.byte2)
        && (byte3 == rhs.byte3) && (byte4 == rhs.byte4));
}

void Http_identifier::init(struct pcap_pkthdr* header,
    const u_char* pkt_data, struct pkt_node* ppkt) {
    this->header = header;
    this->pkt_data = pkt_data;
    this->ppkt = ppkt;
}

int Http_identifier::mac_parse() {
    return 0;
}

int Http_identifier::ip_parse() {
    struct ip_header* ip_protocol;
    int res = 0;
    int tcp_header_length;

    //packet_header是winpcap加上的捕获信息，真正的ip_header还是在packet_content里
    ip_protocol = (struct ip_header*)(pkt_data + 14);//length of ethernet header

    ppkt->saddr = ip_protocol->saddr;
    ppkt->daddr = ip_protocol->daddr;

    return ip_protocol->proto;
}

int Http_identifier::tcp_parse() {
    struct tcp_header* tcp_protocol;
    u_char flags;
    int res;

    //跳过mac协议和ip协议 
    tcp_protocol = (struct tcp_header*)(pkt_data + 14 + 20);
    ppkt->sport = ntohs(tcp_protocol->sport);
    ppkt->dport = ntohs(tcp_protocol->dport);

    ppkt->tcp_header_length = tcp_protocol->offset * 4;
    ppkt->sequence = ntohl(tcp_protocol->sequence);
    //printf("sequence: %d\n", ppkt->sequence);
    flags = tcp_protocol->flags;

    if (flags & 0x08)
    {
        ppkt->tcp_flag = "PSH";
        //cout<<"PSH"<<endl;
        //printf("dport: %d, sport: %d\n", ppkt->dport, ppkt->sport);
        return 0;
    }
    if (flags & 0x10) ppkt->tcp_flag = "ACK";
    if (flags & 0x02) ppkt->tcp_flag = "SYN";
    if (flags & 0x20) ppkt->tcp_flag = "URG";
    if (flags & 0x01) ppkt->tcp_flag = "FIN";   
    if (flags & 0x04) ppkt->tcp_flag = "RST";

    //printf("dport: %d, sport: %d\n", ppkt->dport, ppkt->sport);
    return 0;
}


void Http_reverter::init(struct pcap_pkthdr* header,
    const u_char* pkt_data,
    struct pkt_node* ppkt, char* save_path) {
    this->pkt_data = pkt_data;
    this->header = header;
    this->ppkt = ppkt;
    this->save_path = save_path;
}

void Http_reverter::show_packet() {
    cout << "已还原数据包的内容并保存在路径中\n";
    cout << "请问要查看还原的内容吗？\n";
    cout << "(按1查看，按0继续)\n";
    int input = -1;
    while (input != 0 && input != 1)
        cin >> input;
    if (input) {
        ifstream infile;
        char data[5000];
        try {
            infile.open(body_save_path);
            if (!infile.is_open()) { cout << "Error opening file"; exit(1); }
            while (!infile.eof()) {
                infile >> data;
                cout << data << endl;
            }
            infile.close();
        }
        catch (std::ios_base::failure& e) {
            std::cerr << e.what() << endl;
            cout << e.what() << endl; exit(1);
        }
    }    
}

void Http_reverter::show_info(struct key_word key) {
    int input = -1;
    cout << "请问您还要查看数据包的其他信息吗？\n";
    cout << "(按1查看，按0退出)\n";
    while (input != 0 && input != 1)
        cin >> input;
    if (input) {
        cout << "此次传输对象的数据长度：" << key.Content_Length << endl;
        cout << "此次传输对象的内容类型：" << key.Content_Type << endl;
        if (!strcmp(key.Content_Encoding, "\0"))
            cout << "对象没有加密" << endl;
        else
            cout << "对象使用" << key.Content_Encoding << "加密" << endl;
        if (key.if_chunked)
            cout << "对象使用chunked加密传输" << endl;
    }            
}

int Request_reverter::save_head() {
    int i=0,flag=0;
    http_head_start = 14 + 20 + ppkt->tcp_header_length;
    http_body_start = 0;
    if (http_head_start < header->caplen) {
        /* 将协议头部写入文件后按单词读取 */
        content = (char*)malloc(header->caplen * sizeof(char));
        for (i = http_head_start; i < header->caplen; i++)
        {
            content[i - http_head_start] = pkt_data[i];
            //两个回车表示头部结束
            if (pkt_data[i] == '\r' && pkt_data[i + 1] == '\n' &&
                pkt_data[i + 2] == '\r' && pkt_data[i + 3] == '\n') {
                http_body_start = i + 4;
                content[i - http_head_start] = '\0';
                break;
            }
            printf("%c", pkt_data[i]);
        }
        //判断是不是可读的HTTP头部
        if (strstr(content, "HTTP")) {
            ofstream outfile;
            try {
                outfile.open(save_path);
                outfile << content << endl;
                outfile << "------request http head-----" << endl;
                outfile.close();
            }
            catch (std::ios_base::failure& e) {
                std::cerr << e.what() << endl;
                cout << e.what() << endl;
                exit(1);
            }
            return 0;
        }
    }    
    return 1;
}

int Request_reverter::http_head_parse() {  
    strcpy(key.Content_Encoding, "\0");
    strcpy(key.Content_Length, "\0");
    strcpy(key.Content_Type, "\0");
    ifstream infile;
    try {
        infile.open(save_path);
        infile >> method;
        infile >> URL;
        infile >> http_version;
        
        char  tmp1[2000], tmp2[2000];
        while (infile >> tmp1) {
            int type = match_head(tmp1);
            if (type != 0 && type != 4) infile >> tmp2;
            switch (type) {
            case 1: strcpy(key.Content_Encoding, tmp2); break;
            case 2: strcpy(key.Content_Length, tmp2); break;
            case 3: strcpy(key.Content_Type, tmp2); break;
            case 4: key.if_chunked = 1; break;
            }
        }
        infile.close();
    }
    catch (std::ios_base::failure& e) {
        std::cerr << e.what() << endl;
        return -1;
    }
    cout << "\n捕获到HTTP请求协议\n";
    cout << "方法：" << method << "，URL：" << URL
        << "，HTTP版本：" << http_version << endl;
    if (strcmp(key.Content_Length, "\0")==0) {
        return 1;
    }
    return 0;
}

int Respond_reverter::save_head() {
    int i = 0;
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
            outfile << content << endl;
            outfile.close();
        }
        catch (std::ios_base::failure& e) {
            std::cerr << e.what() << endl;
            cout << e.what() << endl;
            exit(1);
        }
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
    ifstream infile;
    try {
        infile.open(save_path);
        infile >> http_version;
        infile >> status;
        infile >> modifier;
        if (strcmp(status, "200") != 0)
        {       
            cout << "\nHTTP状态码不正确" << endl;
            cout << "错误的状态码是 " << status
                << " " << modifier << endl;
        }
        char  tmp1[2000], tmp2[2000];
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
    }
    catch (std::ios_base::failure& e) {
        std::cerr << e.what() << endl;
        return -1;
    }  
    if (strcmp(key.Content_Length, "\0")==0) {
        return 1;
    }
    return 0;
}

int Http_reverter::match_head(char* s) {
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

int Http_reverter::http_handling(int& mark
    ,struct key_word key_now) {
    int type = 0, encoding = 0;
    if (key.Content_Type) {
        type = match_type(key_now.Content_Type);
        cout << key_now.Content_Type << endl;
    }
    else {
        cout << "还原http首部出错" << endl;
        exit(1);//1表示异常退出，0表示正常退出
    }
    if (strcmp(key.Content_Encoding, "\0")) {
        encoding = 1;
    }
    if (key_now.if_chunked) handle_chunked(mark, type, encoding);
    else {
        int data_len = header->caplen - http_head_start;
        int head_len = http_body_start - http_head_start;
        save_body(mark, type);
        if (ppkt->sequence - start_seq + 
            data_len - head_len < atoi(key_now.Content_Length)) {           
            mark = 1;
        }
        else mark = 0;
    }
    return 0;
}

int Http_reverter::match_type(char* s) {
    if (strstr(s, "image"))
        return 1;
    else if (strstr(s, "application"))
        return 2;
    else if (strstr(s, "text"))
        return 3;
    else
        return 0;
}

/*
* type 1:image 2:application 3:text
*/
int Http_reverter::save_body(int mark, int type) {
    //mark=0表示是数据包的开头，有http头部
    body_save_path = "body.data";
    if (!mark) {
        ofstream outfile;
        try {
            outfile.open(body_save_path,ios::app);
            if (strcmp(key.Content_Encoding, "\0"))
                outfile << "文件被加密了 "
                << key.Content_Encoding << endl;
            outfile << endl;
            outfile << "Date" << __DATE__ << endl;
            outfile << key.Content_Type << endl;
            outfile.close();
        }
        catch (std::ios_base::failure& e) {
            std::cerr << e.what() << endl;
            cout << e.what() << endl;
            exit(1);
        }
    }    
    ofstream outfile;
    try {      
        if (type == 1) {
            //保存图片的后缀名即为图片的格式
            //内容格式image/图片格式，跳过"image/"
            char* picture_type = key.Content_Type + 6;
            cout << picture_type << endl;
            outfile.open(body_save_path, ios::app | ios::binary);
        }
        else {
            outfile.open(body_save_path, ios::app);
        }
        outfile << &pkt_data[http_body_start];
        outfile.close();
    }
    catch (std::ios_base::failure& e) {
        std::cerr << e.what() << endl;
        cout << e.what() << endl;
        exit(1);
    }
    
    return 0;
}

int Http_reverter::handle_chunked(int& mark
    , int type, int encoding) {
    //如果加密了就无法解读头部的chunked信息，只能直接保存当前数据包
    if (encoding) {
        save_body(mark, type);
        mark = 0;
        cout << "已将加密文件保存在指定路径中，请解压缩后查看哟" << endl;
        //exit(0);
    }
    else {

    }       
    return 0;
}


void Analyser::init(struct pkt_node* ppkt,
    struct pcap_pkthdr* header, double dur) {
    this->header = header;
    this->ppkt = ppkt;
    this->dur = dur;
}

void Analyser::analyse_interaction() {
    string CS;
    if (ppkt->dport == 80)
        cout << "\n客户端->服务器\n";
    else
        cout << "\n服务器->客户端\n";
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;

    // convert the timestamp to readable format 
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
    printf("包捕获的时间：%s, 包的总长度：%d\n", timestr, header->len);
    printf("源端口：%d->目的端口：%d\n", ppkt->sport, ppkt->dport);
    printf("源IP：%d->目的IP：%d\n", ppkt->saddr, ppkt->daddr);
    cout << "TCP标志：" << ppkt->tcp_flag << endl;
    cout << "TCP的字节流序号：" << ppkt->sequence << endl;
    cout << "TCP的首部长度：" << ppkt->tcp_header_length << endl;
}

int handle_packet(int func, double dur)
{
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    pcap_t* fp;
    pcap_dumper_t* dumpfile;
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* path = "test.txt";
    char source[PCAP_BUF_SIZE];
    int res = 0;//记录数据包读取的情况，-1表示出错，0表示读取结束 

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
    struct pkt_node first_node;
    //0表示还原request，1表示还原respond
    int req_or_res = -1;
    if (func == 2) {
        cout << "\n请问要还原请求还是应答协议呢？\n";
        cout << "还原请求协议输入0，应答协议输入1\n";
        while (req_or_res != 0 && req_or_res != 1)
            cin >> req_or_res;
    }
  
    // int ret = -1;//记录分片重组函数的返回值
    while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
    {
        /* 
        //调试输出
        for (int i = 0;i < header->caplen; i++) {
            printf("%c", pkt_data[i]);
        }
        cout << endl;
        */
        struct pkt_node pkt;
        struct pkt_node* ppkt;
        ppkt = &pkt;
        int is_HTTP = propotoral_identify(header, pkt_data, ppkt);
        //分析交互功能
        if (func == 1) {
            Analyser aner;
            aner.init(ppkt, header, dur);
            aner.analyse_interaction();           
            continue;
        }
        if (is_HTTP == 0) {
            ;
        }
        else if (is_HTTP == 1) {
            //request http
            if (ppkt->dport == 80 && req_or_res==0) {
                fragment_assemble(req_or_res, mark, start_seq,
                    key_now, first_node,
                    header, pkt_data, ppkt);
            }
            //respond http
            if(ppkt->sport == 80  && req_or_res == 1){
                fragment_assemble(req_or_res, mark, start_seq,
                    key_now, first_node,
                    header, pkt_data, ppkt);
            }
            
        }
    }
    if (mark){
        cout << "已还原部分内容，由于您设置的抓包数量较少，未能重组出完整的分组\n";
        cout << "可增大抓包的数量再重试哟~\n";
    }
               
    if (res == -1){
        printf("在读取转存数据包的文件时发生错误: %s\n", pcap_geterr(fp));
        return -1;
    }

    return 0;       
}

//返回值是1表示重组结束，0表示还在重组中
int fragment_assemble(int req_or_res,int& mark, int& start_seq,
    struct key_word& key_now, struct pkt_node& first_node,
    struct pcap_pkthdr* header,const u_char* pkt_data, 
    struct pkt_node* ppkt) {
    int ret = 0;//记录函数的返回值
    char* head_save_path;
    Http_reverter* preverter;
    if (req_or_res) {
        Respond_reverter reverter;
        preverter = &reverter;
        head_save_path = "test2.txt";
    }
    else {
        Request_reverter reverter;
        preverter = &reverter;
        head_save_path = "test4.txt";
        
    }
    preverter->init(header, pkt_data, ppkt, head_save_path);
    //ret=0表示有http头部，1表示没有
    ret = preverter->save_head();
    //有http头，表示是新数据的开头
    //设置mark，start_seq, key和length
    if (ret == 0) {
        //出现乱序，上一个数据包的数据还未完整接收
        if (mark) {
            cout << "\n出现乱序，放弃本次还原" << endl;
            mark = 0;
            //exit(1);
        }
        else {
            //返回1表示没有body，0表示有body，-1表示读写出错
            ret = preverter->http_head_parse();
            if (ret == 1) {
                //没有body，不用保存body，继续下一轮
                mark = 0;
                preverter->show_packet();
                preverter->show_info(key_now);
                //exit(0);
            }
            else {
                start_seq = ppkt->sequence;
                preverter->start_seq = start_seq;
                key_now = preverter->key;
                first_node = *ppkt;
                preverter->http_handling(mark, key_now);
            }
        }
    }
    else if (ret == 1 && mark == 1) {
        if (ppkt->daddr == first_node.daddr &&
            ppkt->saddr == first_node.saddr ) {
            preverter->http_body_start = preverter->http_head_start;
            preverter->start_seq = start_seq;
            preverter->http_handling(mark, key_now);
        }       
        //mark_res从1变成0说明已获得一个完整的分组
        if (mark == 0) {
            preverter->show_packet();
            preverter->show_info(key_now);
            exit(0);
        }
    }
    return 0;
}


int propotoral_identify(struct pcap_pkthdr* header,
    const u_char* pkt_data, struct pkt_node* ppkt) {
    int res = 0;
    Http_identifier identifier;
    identifier.init(header, pkt_data, ppkt);
    int ip_proto = 0;
    ip_proto = identifier.ip_parse();
    if (ip_proto == 6) identifier.tcp_parse();
    else {
        cout << "is not HTTP" << endl;
        return 0;
    }
    if (ppkt->dport == 80)
    {
        cout << "request HTTP" << endl;
        res = 1;
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




