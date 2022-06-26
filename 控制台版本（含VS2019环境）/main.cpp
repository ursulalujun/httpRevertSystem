#include "capture.h"
#include "revert.h"
#include<windows.h>
#include <iostream>
using namespace std;

int main(){
    int func=0;
    cout << "请问老板想使用什么功能？(输入编号)" << endl;
    cout << "1.分析使用HTTP协议交互的过程" << endl;
    cout << "2.还原使用HTTP协议的数据包内容" << endl;
    while(func!=1&&func!=2)
        cin >> func;
    
    Pkt_capturer Capturer;
    int res = 0;//返回值，0表示正确，-1表示出错

    //获取设备
    res = Capturer.get_device();
    if (res) return -1;

    if (func == 1) {
        Capturer.cnt = 10;
    }
    else {
        cout << "请输入想要抓取的数据包个数，输入0持续抓包，按ctrl-C结束" << endl;
        cin >> Capturer.cnt;
    }
    
    //设置过滤器
    res = Capturer.set_filter(func);
    if (res) return -1;

    //抓取数据包
    res = Capturer.capture_packet(func);
    handle_packet(func, Capturer.dur);
    
    
}



