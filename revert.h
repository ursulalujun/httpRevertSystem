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

    u_char ver_ihl;		// 版本以及首部长度，各4位
    u_char tos;			// 服务质量
    u_short tlen;		// 总长度
    u_short identification;		// 身份识别
    u_short offset;			// 分组偏移
    u_char ttl;			// 生命周期
    u_char proto;		// 协议类型
    u_short checksum;		// 包头测验码
    ip_address saddr;	// 源IP地址
    ip_address daddr;	// 目的IP地址
    u_int op_pad;		//可选 填充字段
}ip_header;

// 保存TCP首部
typedef struct tcp_header {
    u_short sport;
    u_short dport;
    u_int sequence;		// 序列码
    u_int ack;					// 回复码

#ifdef WORDS_BIGENDIAN
    u_char offset : 4, reserved : 4;		// 偏移 预留
#else
    u_char reserved : 4, offset : 4;		// 预留 偏移
#endif

    u_char flags;				// 标志
    u_short windows;			// 窗口大小
    u_short checksum;			// 校验和
    u_short urgent_pointer;		// 紧急指针
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

