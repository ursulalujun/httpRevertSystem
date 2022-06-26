#pragma once
#include "pcap.h"
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
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

/* 保存协议的关键信息 */
struct key_word {
    // 从TCP、IP头部中获取的字节流序号，源/目的IP、端口号等信息
    int seq=0;
    ip_address  saddr;
    ip_address  daddr;
    u_short sport; // 16进制
    u_short dport;
    int head_len = 0;
    // 从HTTP头部中读取的内容类型、长度等信息
    char Content_Type[100]="\0";
    char Content_Length[50] = "\0";
    char Content_Encoding[50] = "\0";
    bool if_chunked=0;

    char http_version[20] = "\0";   //使用的HTTP版本
    char URL[1500] = "\0";          //请求的URL
    char method[20] = "\0";         //请求方法
    char status[10] = "\0";         //应答的状态码
    char modifier[10] = "\0";       //应答的修饰符
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
    u_short sport; // 16进制
    u_short dport;
    ip_address  saddr;      
    ip_address  daddr;      
    u_long sequence;
    string tcp_flag;
    int tcp_header_length;    
};

/* 暂存数据包数据包的结构体 */
struct temp_mem {
    u_long sequence;    //字节流序号
    const u_char* body; //数据包中HTTP协议主体的内容
};

/* 完成识别HTTP协议功能的对象 */
class Http_identifier {
public:
    u_char* argument;
    struct pcap_pkthdr* header; //指向winpcap产生的捕获数据包的首部(存放捕获时间等信息)
    const u_char* pkt_data;     //数据包的内容
    struct pkt_node* ppkt;      //指向被捕获的数据包结点的指针
    void init(struct pcap_pkthdr* header,
        const u_char* pkt_data, struct pkt_node* ppkt);//对象初始化函数
    int mac_parse();            //MAC首部解析
    int ip_parse();             //IP首部解析
    int tcp_parse();            //TCP首部解析
};

/* 完成还原HTTP协议功能的对象 */
class Http_reverter {
public:
    struct pcap_pkthdr* header; //指向winpcap产生的捕获数据包的首部(存放捕获时间等信息)
    struct pkt_node* ppkt;      //指向被捕获的数据包结点的指针
    const u_char* pkt_data;     //数据包的内容
    char* save_path;            //转存数据包的文件路径
    struct key_word key;        //记录HTTP协议关键数据的结点
    char* content;              //记录HTTP首部内容的字符串
    int http_head_start;        //HTTP首部开始的字节数
    int http_body_start;        //HTTP实体部分开始的字节数
    char* body_save_path;       //保存实体部分的文件路径

    //对象初始化函数
    void init(struct pcap_pkthdr* header,
        const u_char* pkt_data,
        struct pkt_node* ppkt, char* save_path); 
    //处理数据包的函数
    int http_handling(int& mark, struct key_word key_now
        , list<temp_mem>& body_list);

    //保存首部的函数
    virtual int save_head() = 0;      //返回值0有http首部,1 没有http首部，-1读写操作出错
    //解析首部的函数
    virtual int http_head_parse() = 0;//返回0状态正确(状态码是200)，1状态出错，-1读写操作出错
    
    //保存实体部分的函数
    int save_body(struct key_word key, list<temp_mem>& body_list);
    //匹配实体内容类型的函数
    int match_head(char* s);
    int match_type(char* s);
  
    //向用户展示协议相关信息的函数
    CString show_info(struct key_word key_now, int res_or_req);
};

/* Http_reverter的子类，还原请求协议 */
class Request_reverter : public Http_reverter {
public:
    int save_head() override;
    int http_head_parse() override;
};

/* Http_reverter的子类，还原应答协议 */
class Respond_reverter : public Http_reverter {
public:   
    int save_head() override;
    int http_head_parse() override;
};

int propotoral_identify(struct pcap_pkthdr* header,
    const u_char* pkt_data, struct pkt_node* ppkt);//数据包识别

int handle_packet(int func, double dur);//数据包还原

