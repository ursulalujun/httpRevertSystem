#pragma once
#include "pcap.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#define LINE_LEN 16
using namespace std;

/* 4 bytes IP address */
struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
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

// ����TCP�ײ�
struct tcp_header {
    u_short sport;
    u_short dport;
    u_int sequence;		// ������
    u_int ack;					// �ظ���

#ifdef WORDS_BIGENDIAN
    u_char offset : 4, reserved : 4;		// ƫ�� Ԥ��
#else
    u_char reserved : 4, offset : 4;		// Ԥ�� ƫ��
#endif

    u_char flags;				// ��־
    u_short windows;			// ���ڴ�С
    u_short checksum;			// У���
    u_short urgent_pointer;		// ����ָ��
};

struct key_word {
    char Content_Type[20];
    char Content_Length[20];
    char Content_Encoding[20];
    bool if_chunked;
};

struct key_mode {
    char* type = "Content-Type:";
    char* length = "Content-Length:";
    char* encoding = "Content-Encoding:";
    char* chunked = "chunked";
};

//class Trie;

int read_file(struct pcap_pkthdr*& header,
    const u_char*& pkt_data);
int ip_revert(u_char* argument,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data);
int tcp_revert(u_char* argument,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data,
    int& tcp_header_length);
int request_revert(u_char* argument,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data,
    int tcp_header_length);
int respond_revert(u_char* argument,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data,
    int tcp_header_length);

//void create_trie(Trie t);
int match_head(char* s);
int match_type(char* s);
int http_head_parse(struct key_word& key);
int http_handling(struct key_word key, const u_char* pkt_data,
    int body_start);
void handle_chunked();
int save_image(struct key_word key, const u_char* pkt_data,
    int body_start);
int save_application(struct key_word key, const u_char* pkt_data,
    int body_start);
int handle_txt(struct key_word key, const u_char* pkt_data,
    int body_start);