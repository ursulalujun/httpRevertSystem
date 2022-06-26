#pragma once
#include "pcap.h"
#include <iostream>
#include <cstring>
using namespace std;

class Pkt_capturer {
public:
    int cnt;
    double dur;
    pcap_if_t* d;
    pcap_t* adhandle;
    pcap_dumper_t* dumpfile;
    int get_device();
    int set_filter(int func);
    int capture_packet(int func);
};

void packet_analysis(u_char* dumpfile,
    const struct pcap_pkthdr* header, const u_char* pkt_data);

// Callback function invoked by libpcap for every incoming packet 
void packet_save(u_char* dumpfile,
    const struct pcap_pkthdr* header, const u_char* pkt_data);