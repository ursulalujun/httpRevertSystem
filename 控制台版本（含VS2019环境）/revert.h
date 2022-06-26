#pragma once
#include "pcap.h"
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#define LINE_LEN 16
using namespace std;

/* 以太网协议格式的定义 */
typedef struct ether_header {
    u_char ether_dhost[6];		// 目标地址
    u_char ether_shost[6];		// 源地址
    u_short ether_type;			// 以太网类型
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
    u_int sequence;		// 序列码
    u_int ack;					// 回复码

#ifdef WORDS_BIGENDIAN // 根据机器的大小端调整存放顺序
    u_char offset : 4, reserved : 4;		// 偏移 预留
#else
    u_char reserved : 4, offset : 4;		// 预留 偏移
#endif

    u_char flags;				// 标志
    u_short windows;			// 窗口大小
    u_short checksum;			// 校验和
    u_short urgent_pointer;		// 紧急指针
};

/* http头部中的关键字 */
struct key_word {
    int seq=0;
    char Content_Type[50];
    char Content_Length[20];
    char Content_Encoding[50];
    bool if_chunked=0;
};

/* 关键字匹配模式串 */
struct key_mode {
    char* type = "Content-Type:";
    char* length = "Content-Length:";
    char* encoding = "Content-Encoding:";
    char* chunked = "chunked";
};

/* 存放数据包重要信息的结点 */
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
    virtual int save_head() = 0;//返回值0有http头,1 没有http头，-1读写操作出错
    virtual int http_head_parse() = 0;//返回0状态正确，1状态出错，-1读写操作出错
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
    const u_char* pkt_data, struct pkt_node* ppkt);//数据包识别

int handle_packet(int func, double dur);//数据包还原

int fragment_assemble(int req_or_res, int& mark, int& start_seq,
    struct key_word& key_now, struct pkt_node& first_node,
    struct pcap_pkthdr* header, const u_char* pkt_data,
    struct pkt_node* ppkt);
