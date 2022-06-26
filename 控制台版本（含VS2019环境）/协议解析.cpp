# include "revert.h"
# include <string>
#include <iostream>
#include <fstream>
using namespace std;

//����==���������Ƚ�ip_address
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

    //packet_header��winpcap���ϵĲ�����Ϣ��������ip_header������packet_content��
    ip_protocol = (struct ip_header*)(pkt_data + 14);//length of ethernet header

    ppkt->saddr = ip_protocol->saddr;
    ppkt->daddr = ip_protocol->daddr;

    return ip_protocol->proto;
}

int Http_identifier::tcp_parse() {
    struct tcp_header* tcp_protocol;
    u_char flags;
    int res;

    //����macЭ���ipЭ�� 
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
    cout << "�ѻ�ԭ���ݰ������ݲ�������·����\n";
    cout << "����Ҫ�鿴��ԭ��������\n";
    cout << "(��1�鿴����0����)\n";
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
    cout << "��������Ҫ�鿴���ݰ���������Ϣ��\n";
    cout << "(��1�鿴����0�˳�)\n";
    while (input != 0 && input != 1)
        cin >> input;
    if (input) {
        cout << "�˴δ����������ݳ��ȣ�" << key.Content_Length << endl;
        cout << "�˴δ��������������ͣ�" << key.Content_Type << endl;
        if (!strcmp(key.Content_Encoding, "\0"))
            cout << "����û�м���" << endl;
        else
            cout << "����ʹ��" << key.Content_Encoding << "����" << endl;
        if (key.if_chunked)
            cout << "����ʹ��chunked���ܴ���" << endl;
    }            
}

int Request_reverter::save_head() {
    int i=0,flag=0;
    http_head_start = 14 + 20 + ppkt->tcp_header_length;
    http_body_start = 0;
    if (http_head_start < header->caplen) {
        /* ��Э��ͷ��д���ļ��󰴵��ʶ�ȡ */
        content = (char*)malloc(header->caplen * sizeof(char));
        for (i = http_head_start; i < header->caplen; i++)
        {
            content[i - http_head_start] = pkt_data[i];
            //�����س���ʾͷ������
            if (pkt_data[i] == '\r' && pkt_data[i + 1] == '\n' &&
                pkt_data[i + 2] == '\r' && pkt_data[i + 3] == '\n') {
                http_body_start = i + 4;
                content[i - http_head_start] = '\0';
                break;
            }
            printf("%c", pkt_data[i]);
        }
        //�ж��ǲ��ǿɶ���HTTPͷ��
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
    cout << "\n����HTTP����Э��\n";
    cout << "������" << method << "��URL��" << URL
        << "��HTTP�汾��" << http_version << endl;
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
        /* ��Э��ͷ��д���ļ��󰴵��ʶ�ȡ */
        content = (char*)malloc(header->caplen * sizeof(char));
        for (i = http_head_start; i < header->caplen; i++)
        {
            //�����س���ʾͷ������
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
    //��ʼ��key�е�ֵΪ0����0��ʾhttpͷ��û�г��ָ�ֵ
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
            cout << "\nHTTP״̬�벻��ȷ" << endl;
            cout << "�����״̬���� " << status
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
        cout << "��ԭhttp�ײ�����" << endl;
        exit(1);//1��ʾ�쳣�˳���0��ʾ�����˳�
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
    //mark=0��ʾ�����ݰ��Ŀ�ͷ����httpͷ��
    body_save_path = "body.data";
    if (!mark) {
        ofstream outfile;
        try {
            outfile.open(body_save_path,ios::app);
            if (strcmp(key.Content_Encoding, "\0"))
                outfile << "�ļ��������� "
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
            //����ͼƬ�ĺ�׺����ΪͼƬ�ĸ�ʽ
            //���ݸ�ʽimage/ͼƬ��ʽ������"image/"
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
    //��������˾��޷����ͷ����chunked��Ϣ��ֻ��ֱ�ӱ��浱ǰ���ݰ�
    if (encoding) {
        save_body(mark, type);
        mark = 0;
        cout << "�ѽ������ļ�������ָ��·���У����ѹ����鿴Ӵ" << endl;
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
        cout << "\n�ͻ���->������\n";
    else
        cout << "\n������->�ͻ���\n";
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;

    // convert the timestamp to readable format 
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
    printf("�������ʱ�䣺%s, �����ܳ��ȣ�%d\n", timestr, header->len);
    printf("Դ�˿ڣ�%d->Ŀ�Ķ˿ڣ�%d\n", ppkt->sport, ppkt->dport);
    printf("ԴIP��%d->Ŀ��IP��%d\n", ppkt->saddr, ppkt->daddr);
    cout << "TCP��־��" << ppkt->tcp_flag << endl;
    cout << "TCP���ֽ�����ţ�" << ppkt->sequence << endl;
    cout << "TCP���ײ����ȣ�" << ppkt->tcp_header_length << endl;
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
    int res = 0;//��¼���ݰ���ȡ�������-1��ʾ����0��ʾ��ȡ���� 

    /* ��ȡת������ݰ� */
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
        PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode ���ģʽ
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
    //0��ʾ��ԭrequest��1��ʾ��ԭrespond
    int req_or_res = -1;
    if (func == 2) {
        cout << "\n����Ҫ��ԭ������Ӧ��Э���أ�\n";
        cout << "��ԭ����Э������0��Ӧ��Э������1\n";
        while (req_or_res != 0 && req_or_res != 1)
            cin >> req_or_res;
    }
  
    // int ret = -1;//��¼��Ƭ���麯���ķ���ֵ
    while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
    {
        /* 
        //�������
        for (int i = 0;i < header->caplen; i++) {
            printf("%c", pkt_data[i]);
        }
        cout << endl;
        */
        struct pkt_node pkt;
        struct pkt_node* ppkt;
        ppkt = &pkt;
        int is_HTTP = propotoral_identify(header, pkt_data, ppkt);
        //������������
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
        cout << "�ѻ�ԭ�������ݣ����������õ�ץ���������٣�δ������������ķ���\n";
        cout << "������ץ��������������Ӵ~\n";
    }
               
    if (res == -1){
        printf("�ڶ�ȡת�����ݰ����ļ�ʱ��������: %s\n", pcap_geterr(fp));
        return -1;
    }

    return 0;       
}

//����ֵ��1��ʾ���������0��ʾ����������
int fragment_assemble(int req_or_res,int& mark, int& start_seq,
    struct key_word& key_now, struct pkt_node& first_node,
    struct pcap_pkthdr* header,const u_char* pkt_data, 
    struct pkt_node* ppkt) {
    int ret = 0;//��¼�����ķ���ֵ
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
    //ret=0��ʾ��httpͷ����1��ʾû��
    ret = preverter->save_head();
    //��httpͷ����ʾ�������ݵĿ�ͷ
    //����mark��start_seq, key��length
    if (ret == 0) {
        //����������һ�����ݰ������ݻ�δ��������
        if (mark) {
            cout << "\n�������򣬷������λ�ԭ" << endl;
            mark = 0;
            //exit(1);
        }
        else {
            //����1��ʾû��body��0��ʾ��body��-1��ʾ��д����
            ret = preverter->http_head_parse();
            if (ret == 1) {
                //û��body�����ñ���body��������һ��
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
        //mark_res��1���0˵���ѻ��һ�������ķ���
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




