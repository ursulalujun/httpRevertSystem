#include "pcap.h"

void home_screen();
int packet_capture(int cnt);
int packet_revert();

int main(){
    int cnt;
    int is_HTTP;
    scanf("%d", &cnt);
    packet_capture(cnt);
    packet_revert();
    
}

