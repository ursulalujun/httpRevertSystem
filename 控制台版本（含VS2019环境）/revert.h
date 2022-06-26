#pragma once
#include "pcap.h"
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#define LINE_LEN 16
using namespace std;

/* ��̫��Э���ʽ�Ķ��� */
typedef struct ether_header {
    u_char ether_dhost[6];		// Ŀ���ַ
    u_char ether_shost[6];		// Դ��ַ
    u_short ether_type;			// ��̫������
}ether_header;

/* 4 bytes IP address */
struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    bool operator == (const ip_address& rhs);
};


/* IPv4 header */
struct ip_header {
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
};

/* TCP header */ 
struct tcp_header {
    u_short sport;
    u_short dport;    
    u_int sequence;		// ������
    u_int ack;					// �ظ���

#ifdef WORDS_BIGENDIAN // ���ݻ����Ĵ�С�˵������˳��
    u_char offset : 4, reserved : 4;		// ƫ�� Ԥ��
#else
    u_char reserved : 4, offset : 4;		// Ԥ�� ƫ��
#endif

    u_char flags;				// ��־
    u_short windows;			// ���ڴ�С
    u_short checksum;			// У���
    u_short urgent_pointer;		// ����ָ��
};

/* httpͷ���еĹؼ��� */
struct key_word {
    int seq=0;
    char Content_Type[50];
    char Content_Length[20];
    char Content_Encoding[50];
    bool if_chunked=0;
};

/* �ؼ���ƥ��ģʽ�� */
struct key_mode {
    char* type = "Content-Type:";
    char* length = "Content-Length:";
    char* encoding = "Content-Encoding:";
    char* chunked = "chunked";
};

/* ������ݰ���Ҫ��Ϣ�Ľ�� */
struct pkt_node {
    u_short sport;
    u_short dport;
    ip_address  saddr;      
    ip_address  daddr;      
    u_long sequence;
    string tcp_flag;
    int tcp_header_length;    
};

class Analyser {
public:
    struct pkt_node* ppkt;
    struct pcap_pkthdr* header;
    double dur;
    void init(struct pkt_node* ppkt,
        struct pcap_pkthdr* header, double dur);
    void analyse_interaction();
};

class Http_identifier {
public:
    u_char* argument; 
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    struct pkt_node* ppkt;
    void init(struct pcap_pkthdr* header,
        const u_char* pkt_data, struct pkt_node* ppkt);
    int mac_parse();
    int ip_parse();
    int tcp_parse();
};

class Http_reverter {
public:
    struct pcap_pkthdr* header;
    struct pkt_node* ppkt;
    const u_char* pkt_data;
    char* save_path;

    struct key_word key;
    int start_seq;
    char* content;
    int http_head_start;
    int http_body_start;
    char* body_save_path;
    void init(struct pcap_pkthdr* header,
        const u_char* pkt_data,
        struct pkt_node* ppkt, char* save_path);
    virtual int save_head() = 0;//����ֵ0��httpͷ,1 û��httpͷ��-1��д��������
    virtual int http_head_parse() = 0;//����0״̬��ȷ��1״̬����-1��д��������
    int http_handling(int& mark, struct key_word key_now);
    int match_head(char* s);
    int match_type(char* s);
    int save_body(int mark, int type);
    int handle_chunked(int& mark, int type, int encoding);
    void show_packet();
    void show_info(struct key_word key_now);
};

class Request_reverter : public Http_reverter {
public:
    char URL[1500] = "\0";
    char method[50] = "\0";
    char http_version[50] = "\0";
    int save_head() override;
    int http_head_parse() override;
};


class Respond_reverter : public Http_reverter {
public:
    char http_version[50] = "\0";
    char status[50] = "\0";
    char modifier[50] = "\0";
    int save_head() override;
    int http_head_parse() override;
};

int propotoral_identify(struct pcap_pkthdr* header,
    const u_char* pkt_data, struct pkt_node* ppkt);//���ݰ�ʶ��

int handle_packet(int func, double dur);//���ݰ���ԭ

int fragment_assemble(int req_or_res, int& mark, int& start_seq,
    struct key_word& key_now, struct pkt_node& first_node,
    struct pcap_pkthdr* header, const u_char* pkt_data,
    struct pkt_node* ppkt);
