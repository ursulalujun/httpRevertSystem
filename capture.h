#pragma once
#include "pcap.h"

class Pkt_capturer {
public:
    int cnt;
    pcap_if_t* d;
    pcap_t* adhandle;
    pcap_dumper_t* dumpfile;
    int get_device();
    int set_filter();
    int save_packet();
};

// Callback function invoked by libpcap for every incoming packet 
void packet_handler(u_char* dumpfile,
    const struct pcap_pkthdr* header, const u_char* pkt_data);