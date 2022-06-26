#include "capture.h"
#include <time.h> 

int Pkt_capturer::get_device(){
    pcap_if_t* alldevs;
    int inum;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    /* Retrieve the device list */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for (d = alldevs; d; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nû�в��ҵ��κ��豸������winPcap�Ƿ���ȷ��װ.\n");
        return -1;
    }

    printf("��������Ҫ�������豸��� (1-%d):", i);
    scanf_s("%d", &inum);

    if (inum < 1 || inum > i)
    {
        printf("\n����ı�ų����˷�Χ������������.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for (d = alldevs, i = 0; i < inum - 1;d = d->next, i++);

    /* Open the adapter */
    if ((adhandle = pcap_open(d->name,  // name of the device
        65536,     // portion of the packet to capture. 
                   // 65536 grants that the whole packet will be captured on all the MACs.
        PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
        1000,      // read timeout
        NULL,      // remote authentication
        errbuf     // error buffer
    )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
        printf("\n�޷�������������. WinPcap��֧�ָ��豸\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    return 0;
}

int Pkt_capturer::set_filter(int func){
    u_int netmask;
    if (func == 2) {
        cout << "�����Ƿ�Ҫ���ù�������ʹ�ù����������󲶻�ʹ��HTTPЭ������ݰ��ĸ���Ӵ��~��" << endl;
        cout << "���Ҫʹ��������1����ʹ��������0" << endl;
        int isf=3;
        while(isf!=0&&isf!=1)
            cin >> isf;
        if (isf == 0) return 0;
    }
    char packet_filter[] = "tcp port 80";//��û��ָ����Ĭ��dst or src
    struct bpf_program fcode;
    /* Check the link layer. We support only Ethernet for simplicity. */
    if (pcap_datalink(adhandle) != DLT_EN10MB)
    {
        fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
        return -1;
    }

    if (d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        /* If the interface is without addresses we suppose to be in a C class network */
        netmask = 0xffffff;

    /*compile the filter*/
    if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
    {
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
        return -1;
    }

    /* set the filter */
    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr, "\nError setting the filter.\n");
        return -1;
    }

    printf("\n���ڼ��� %s...\n", d->description);
    return 0;
}

int Pkt_capturer::capture_packet(int func){
    cout << "�����뻺�����ݰ���·��" << endl;
    const char* path = "test.txt";
    dumpfile = pcap_dump_open(adhandle, path);
    clock_t start, end;
    start = clock();
    /* ץ��+ת��*/
    pcap_loop(adhandle, cnt, packet_save, (unsigned char*)dumpfile);
    end = clock();
    dur = (double)(end - start);    
    return 0;
}


void packet_save(u_char* dumpfile,
    const struct pcap_pkthdr* header, const u_char* pkt_data){
    
    // save the packet on the dump file 
    pcap_dump(dumpfile, header, pkt_data);

}

/*
void packet_analysis(u_char* dumpfile,
    const struct pcap_pkthdr* header, const u_char* pkt_data) {
    struct tm ltime;
    char timestr[16];
    time_t local_tv_sec;
    u_int i = 0;

    // convert the timestamp to readable format 
    local_tv_sec = header->ts.tv_sec;
    localtime_s(&ltime, &local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
    printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
}
*/

