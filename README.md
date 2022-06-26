# httpRevertSystem

UESTC综合课程设计

转载论文、ppt中的文字或流程图请标注原作者，谢谢！

项目完成的基本功能：

1、捕获网络数据包，并识别HTTP协议。
2、设计还原算法。
3、编程实现该算法。

3.27面向对象版本是控制台程序，后续又增加了用MFC编写的GUI界面

本文档介绍了使用winpcap库捕获数据包的方式，更多设计思路和原理解析请参考综合课程设计论文和汇报PPT

### 配置winPcap库

1.下载并安装winPcap程序

注意一定要勾选

2.下载工具包，在VS2019中配置，在项目属性附加库中添加wpcap.dll和Packet.dll，包含目录中添加include，库目录中添加Lib

### 数据包捕获

#### 原理

WinPcap简介：

为了能够访问网络上传输的原始数据，数据包捕获系统需要绕过操作系统的协议栈，这就需要有一部分程序直接运行在操作系统的内容中，只有这样才能直接与网络接口驱动直接交互。NPF的设备驱动程序

NPF的主要功能数据包的过滤、发送、网络统计、数据包转储到磁盘

Packet.dll库提供底层的API，用来直接访问驱动程序的函数。 

#### 流程

1. 获取设备状态，选择设备

获取附加的网络适配器的列表， `pcap_findalldevs_ex（）` 函数：此函数返回`pcap_if`结构的链接列表，有一个 *errbuf* 参数。此参数指向由 libpcap 填充的字符串，其中包含出错时的错误描述。

当我们完成列表时，我们用`pcap_freealldevs（）`释放一次列表。

似乎一种设备最后只会有一个适配器是在工作的

2. 接收数据包

有三种方式可以实现，为了能够处理错误信息，选择过滤器+非回调抓包

1）捕获函数+回调函数packet_handler

```c
typedef void（* pcap_handler）（u_char *user， const struct pcap_pkthdr *pkt_header， const u_char *pkt_data）
```

接收数据包的回调函数的原型确定，函数体需要自己编写。对协议的解释、数据包的转存都可以写在这个回调函数里。

当用户调用 pcap_dispatch（） 或 pcap_loop（） 时，数据包通过此回调传递到应用程序。user 是包含捕获会话状态的用户定义参数，它对应于 pcap_dispatch（） 和 pcap_loop（） *的用户*参数。pcap_pkthdr是捕获驱动程序与数据包关联的标头。它不是协议标头。pkt_data指向数据包的数据，包括协议标头。

2）捕获函数+非回调函数，这种尤其适用于pcap_loop遇到障碍的时候，pcap_loop直接由NPF驱动程序调用，应用程序不能直接控制它，只能使用pcap_next_ex接收到数据包（是由于部分信息缺失，所以回调函数的参数不够无法触发回调吗？）

pcap_next_ex也可以不依赖pcap_dispatch（） 或 pcap_loop（）直接使用

pcap_next_ex返回报错信息：

- 1 if the packet has been read without problems
- 0 if the timeout set with pcap_open_live() has elapsed. In this case pkt_header and pkt_data don't point to a valid packet
- -1 if an error occurred，可以再调用**pcap_geterr**来return the error text pertaining to the last pcap library error.或者**pcap_perror**开启套接字，等待下一个连接
- -2 if EOF was reached reading from an offline capture

断开网络好像会返回错误0

3）添加过滤器接收

pcap_compile（） 采用包含高级布尔（筛选器）表达式的字符串，并生成可由数据包驱动程序中的文件管理器引擎解释的低级字节代码。布尔表达式的语法可在本文档的[筛选表达式语法](https://www.winpcap.org/docs/docs_412/html/group__language.html)部分找到。

pcap_setfilter（） 将筛选器与内核驱动程序中的捕获会话相关联。

返回值 -1 表示出现错误，在这种情况下，可以使用 pcap_geterr（） 来显示错误文本。

HTTP协议采用TCP连接，所以只保留TCP会话

过滤以太网协议->IP协议->TCP协议

3. 保存数据包

使用pcap_open_offline()、pcap_dump_open()等函数可以打开保存捕获数据包的文件进行读取和分析，使用pcap_dump()函数可以将捕获的数据包保存到文件中。还有其他接口可以对网络数据链路层类型进行探测，对捕获数据包的情况进  ——引自 向宇

pcap_loop本质应该是循环读取数据包（排序？），然后触发回调，回调函数对信息进行处理（转存、解析、打印），抓包就是监听+读取，也可以用pcap_loop读取转存的数据包

转存文件使用 pcap_open_offline（）打开，使用pcap_loop或者pcap_next_ex读取。

函数pcap_createsrcsrc（）需要创建一个源字符串，该字符串以用于告诉 WinPcap 源类型的标记开头，例如，如果我们要打开适配器，则为"rpcap://"，如果要打开文件，则为"file://"。使用 pcap_findalldevs_ex（） 时，不需要执行此步骤（返回的值已包含这些字符串）。但是，在此示例中需要它，因为文件的名称是从用户输入中读取的。

#### WinPcap的结构体

pcap_if 记录设备信息，包括名字，描述，地址，接口标志

```c
struct pcap_if {
     struct pcap_if *next; 
     char *name;     
     char *description;  
     struct pcap_addr *addresses; 
     u_int flags;        
};
```



pcap_pkthdr捕获驱动程序与数据包关联的标头

```c
struct pcap_pkthdr {
     struct timeval ts;  //捕获时间
     bpf_u_int32 caplen; //时间戳
     bpf_u_int32 len;    //长度
 };
```



真正存放捕获实例的这个结构体比较神奇

```c
typedef struct pcap pcap_t
```

打开的捕获实例的描述符。此结构对用户**来说是不透明的**，它通过wpcap.dll提供的功能来处理其内容。

pcap, pcap_dumper好像都是和内核相关连的，用户看不见的结构



#### pcap文件格式

### 协议还原

winpcap是在链路层抓包，所以从mac开始识别，一层层的去头

#### 识别http协议

MAC协议解析模块根据以太网帧格式提取数据包以太网头部的类型字段，用于判断网络协议层协议是否为IP协议

```c
	u_short ethernet_type;		// 以太网类型
	struct ether_header* ethernet_protocol;		// 以太网协议变量
	u_char* mac_string;			// 以太网地址

	ethernet_protocol = (struct ether_header*)packet_content;		// 获取以太网数据内容
	printf("Ethernet type is : \n");
	ethernet_type = ntohs(ethernet_protocol->ether_type);	// 获取以太网类型
	printf("	%04x\n", ethernet_type);

	switch (ethernet_type) {
	case 0x0800:
		printf("The network layer is IP protocol\n");
		break;
	case 0x0806:
		printf("The network layer is ARP protocol\n");
		break;
	default:
		break;
	}
```



IP协议结构

![image-20220307193603455](https://s2.loli.net/2022/03/07/yH9VCkGvB17mO4t.png)

```c
	ip_protocol = (struct ip_header*)(packet_content + 14);
    header_length = ip_protocol->header_length * 4;
	//?
    checksum = ntohs(ip_protocol->checksum);
    tos = ip_protocol->tos;
    offset = ntohs(ip_protocol->offset);
//ip_header结构体里这是什么意思？
#ifdef WORDS_BIGENDIAN
    u_char ip_version : 4, header_length : 4;
#else
    u_char header_length : 4, ip_version : 4;
#endif
```

TCP协议结构

![image-20220309110151910](https://s2.loli.net/2022/03/09/yJbQgrOMUowpj9a.png)

只需要识别出http协议，TCP协议+端口号80应该就可以了，使用过滤器直接过滤出TCP协议，从TCP协议开始解析即可，使用过滤好像就可以跳过解析IP和MAC

```c
    /* retireve the position of the ip header */
    ih = (ip_header*)(pkt_data +
        14); //length of ethernet header

    /* retireve the position of the udp header */
    ip_len = (ih->ver_ihl & 0xf) * 4;
    uh = (udp_header*)((u_char*)ih + ip_len);

    /* convert from network byte order to host byte order */
    sport = ntohs(uh->sport);
    dport = ntohs(uh->dport);
```

甚至可以不用层层解析，直接过滤就行`tcp port 80`

对数据包(pacp格式)中的数据，按照五元组（#流：源端口号、目的端口号、协议号、源IP、目的IP）对流进行划分。

80端口不只传输超文本，也传输TCP标志为PSH的DATA数据，http也不一定要用80端口

