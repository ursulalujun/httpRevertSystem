#include "capture.h"
#include "revert.h"
#include<windows.h>
#include <iostream>
using namespace std;

int main(){
    int func=0;
    cout << "�����ϰ���ʹ��ʲô���ܣ�(������)" << endl;
    cout << "1.����ʹ��HTTPЭ�齻���Ĺ���" << endl;
    cout << "2.��ԭʹ��HTTPЭ������ݰ�����" << endl;
    while(func!=1&&func!=2)
        cin >> func;
    
    Pkt_capturer Capturer;
    int res = 0;//����ֵ��0��ʾ��ȷ��-1��ʾ����

    //��ȡ�豸
    res = Capturer.get_device();
    if (res) return -1;

    if (func == 1) {
        Capturer.cnt = 10;
    }
    else {
        cout << "��������Ҫץȡ�����ݰ�����������0����ץ������ctrl-C����" << endl;
        cin >> Capturer.cnt;
    }
    
    //���ù�����
    res = Capturer.set_filter(func);
    if (res) return -1;

    //ץȡ���ݰ�
    res = Capturer.capture_packet(func);
    handle_packet(func, Capturer.dur);
    
    
}



