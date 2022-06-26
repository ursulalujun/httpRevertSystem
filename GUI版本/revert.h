#pragma once
#include "pcap.h"
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <list>
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

/* ����Э��Ĺؼ���Ϣ */
struct key_word {
    // ��TCP��IPͷ���л�ȡ���ֽ�����ţ�Դ/Ŀ��IP���˿ںŵ���Ϣ
    int seq=0;
    ip_address  saddr;
    ip_address  daddr;
    u_short sport; // 16����
    u_short dport;
    int head_len = 0;
    // ��HTTPͷ���ж�ȡ���������͡����ȵ���Ϣ
    char Content_Type[100]="\0";
    char Content_Length[50] = "\0";
    char Content_Encoding[50] = "\0";
    bool if_chunked=0;

    char http_version[20] = "\0";   //ʹ�õ�HTTP�汾
    char URL[1500] = "\0";          //�����URL
    char method[20] = "\0";         //���󷽷�
    char status[10] = "\0";         //Ӧ���״̬��
    char modifier[10] = "\0";       //Ӧ������η�
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
    u_short sport; // 16����
    u_short dport;
    ip_address  saddr;      
    ip_address  daddr;      
    u_long sequence;
    string tcp_flag;
    int tcp_header_length;    
};

/* �ݴ����ݰ����ݰ��Ľṹ�� */
struct temp_mem {
    u_long sequence;    //�ֽ������
    const u_char* body; //���ݰ���HTTPЭ�����������
};

/* ���ʶ��HTTPЭ�鹦�ܵĶ��� */
class Http_identifier {
public:
    u_char* argument;
    struct pcap_pkthdr* header; //ָ��winpcap�����Ĳ������ݰ����ײ�(��Ų���ʱ�����Ϣ)
    const u_char* pkt_data;     //���ݰ�������
    struct pkt_node* ppkt;      //ָ�򱻲�������ݰ�����ָ��
    void init(struct pcap_pkthdr* header,
        const u_char* pkt_data, struct pkt_node* ppkt);//�����ʼ������
    int mac_parse();            //MAC�ײ�����
    int ip_parse();             //IP�ײ�����
    int tcp_parse();            //TCP�ײ�����
};

/* ��ɻ�ԭHTTPЭ�鹦�ܵĶ��� */
class Http_reverter {
public:
    struct pcap_pkthdr* header; //ָ��winpcap�����Ĳ������ݰ����ײ�(��Ų���ʱ�����Ϣ)
    struct pkt_node* ppkt;      //ָ�򱻲�������ݰ�����ָ��
    const u_char* pkt_data;     //���ݰ�������
    char* save_path;            //ת�����ݰ����ļ�·��
    struct key_word key;        //��¼HTTPЭ��ؼ����ݵĽ��
    char* content;              //��¼HTTP�ײ����ݵ��ַ���
    int http_head_start;        //HTTP�ײ���ʼ���ֽ���
    int http_body_start;        //HTTPʵ�岿�ֿ�ʼ���ֽ���
    char* body_save_path;       //����ʵ�岿�ֵ��ļ�·��

    //�����ʼ������
    void init(struct pcap_pkthdr* header,
        const u_char* pkt_data,
        struct pkt_node* ppkt, char* save_path); 
    //�������ݰ��ĺ���
    int http_handling(int& mark, struct key_word key_now
        , list<temp_mem>& body_list);

    //�����ײ��ĺ���
    virtual int save_head() = 0;      //����ֵ0��http�ײ�,1 û��http�ײ���-1��д��������
    //�����ײ��ĺ���
    virtual int http_head_parse() = 0;//����0״̬��ȷ(״̬����200)��1״̬����-1��д��������
    
    //����ʵ�岿�ֵĺ���
    int save_body(struct key_word key, list<temp_mem>& body_list);
    //ƥ��ʵ���������͵ĺ���
    int match_head(char* s);
    int match_type(char* s);
  
    //���û�չʾЭ�������Ϣ�ĺ���
    CString show_info(struct key_word key_now, int res_or_req);
};

/* Http_reverter�����࣬��ԭ����Э�� */
class Request_reverter : public Http_reverter {
public:
    int save_head() override;
    int http_head_parse() override;
};

/* Http_reverter�����࣬��ԭӦ��Э�� */
class Respond_reverter : public Http_reverter {
public:   
    int save_head() override;
    int http_head_parse() override;
};

int propotoral_identify(struct pcap_pkthdr* header,
    const u_char* pkt_data, struct pkt_node* ppkt);//���ݰ�ʶ��

int handle_packet(int func, double dur);//���ݰ���ԭ

