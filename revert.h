#pragma once
#include "pcap.h"
#define LINE_LEN 16

/* 4 bytes IP address */
typedef struct ip_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header {
#ifdef WORDS_BIGENDIAN
    u_char ip_version : 4, header_length : 4;
#else
    u_char header_length : 4, ip_version : 4;
#endif

    u_char ver_ihl;		// �汾�Լ��ײ����ȣ���4λ
    u_char tos;			// ��������
    u_short tlen;		// �ܳ���
    u_short identification;		// ���ʶ��
    u_short offset;			// ����ƫ��
    u_char ttl;			// ��������
    u_char proto;		// Э������
    u_short checksum;		// ��ͷ������
    ip_address saddr;	// ԴIP��ַ
    ip_address daddr;	// Ŀ��IP��ַ
    u_int op_pad;		//��ѡ ����ֶ�
}ip_header;

// ����TCP�ײ�
typedef struct tcp_header {
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
}tcp_header;

int read_file(struct pcap_pkthdr*& header,
    const u_char*& pkt_data);
int ip_revert(u_char* argument,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data);
int tcp_revert(u_char* argument,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data);
int http_revert(u_char* argument,
    const struct pcap_pkthdr* header,
    const u_char* pkt_data);

