#pragma once
#include "pcap.h"

int packet_capture(int cnt);
int get_device(pcap_if_t*& d, pcap_t*& adhandle);
int set_filter(pcap_if_t*& d, pcap_t*& adhandle);
int save_packet(pcap_t*& adhandle, int cnt);
void packet_handler(u_char* dumpfile, const struct pcap_pkthdr* header, const u_char* pkt_data);
