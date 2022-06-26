// menu.cpp: 实现文件
//

#include "pch.h"
#include "MFCApplication2.h"
#include "menu.h"
#include "afxdialogex.h"
#include "pcap.h"
#include "revert.h"
# include <string>
#include <iostream>
#include <fstream>

// menu 对话框

IMPLEMENT_DYNAMIC(menu, CDialogEx)

menu::menu(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DIALOG1, pParent)
{

}

menu::~menu()
{
}

void menu::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, danalysis);
}


BEGIN_MESSAGE_MAP(menu, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON4, &menu::OnBnClickedButton4)
	ON_BN_CLICKED(IDC_BUTTON5, &menu::OnBnClickedButton5)
	ON_BN_CLICKED(IDC_BUTTON1, &menu::OnBnClickedButton1)
END_MESSAGE_MAP()


//重载==操作符，比较ip_address
bool ip_address::operator == (const ip_address& rhs)
{
	return ((byte1 == rhs.byte1) && (byte2 == rhs.byte2)
		&& (byte3 == rhs.byte3) && (byte4 == rhs.byte4));
}

/* Http_identifier类的成员函数 */
void Http_identifier::init(struct pcap_pkthdr* header,
	const u_char* pkt_data, struct pkt_node* ppkt) {
	this->header = header;
	this->pkt_data = pkt_data;
	this->ppkt = ppkt;
}

int Http_identifier::mac_parse() {
	struct ether_header* eth_protocol;
	eth_protocol = (struct ether_header*)(pkt_data);
	return 0;
}

int Http_identifier::ip_parse() {
	struct ip_header* ip_protocol;

	//packet_header是winpcap加上的捕获信息，真正的ip_header还是在packet_content里
	ip_protocol = (struct ip_header*)(pkt_data + 14);//length of ethernet header

	ppkt->saddr = ip_protocol->saddr;
	ppkt->daddr = ip_protocol->daddr;

	return ip_protocol->proto;
}

int Http_identifier::tcp_parse() {
	struct tcp_header* tcp_protocol;
	u_char flags;

	//跳过mac协议和ip协议 
	tcp_protocol = (struct tcp_header*)(pkt_data + 14 + 20);
	ppkt->sport = ntohs(tcp_protocol->sport);
	ppkt->dport = ntohs(tcp_protocol->dport);

	ppkt->tcp_header_length = tcp_protocol->offset * 4;
	ppkt->sequence = ntohl(tcp_protocol->sequence);
	flags = tcp_protocol->flags;

	if (flags & 0x08)
	{
		ppkt->tcp_flag = "PSH";
		return 0;
	}
	if (flags & 0x10) ppkt->tcp_flag = "ACK";
	if (flags & 0x02) ppkt->tcp_flag = "SYN";
	if (flags & 0x20) ppkt->tcp_flag = "URG";
	if (flags & 0x01) ppkt->tcp_flag = "FIN";
	if (flags & 0x04) ppkt->tcp_flag = "RST";

	return 0;
}

/* Http_reverter类的成员函数 */
void Http_reverter::init(struct pcap_pkthdr* header,
    const u_char* pkt_data,
    struct pkt_node* ppkt, char* save_path) {
    this->pkt_data = pkt_data;
    this->header = header;
    this->ppkt = ppkt;
    this->save_path = save_path;
}

CString Http_reverter::show_info(struct key_word key, int res_or_req) {
	CString temp;
	temp = temp + L"\r\n已还原数据包的内容并保存在指定路径中\r\n";
	if (res_or_req == 0) {
		temp = temp + L"请打开respond_head.txt文件查看协议头部\r\n";
	}
	else {
		temp = temp + L"请打开request_head.txt文件查看协议头部\r\n";
	}
	temp = temp + L"请打开body.data文件查看协议实体部分\r\n";
	temp = temp + L"数据包的信息如下：\r\n"
		+ "此次传输对象的数据长度：" + (CString)key.Content_Length
		+ "\r\n此次传输对象的内容类型：" + (CString)key.Content_Type;
    if (!strcmp(key.Content_Encoding, "\0"))
        temp = temp + L"对象没有加密\r\n" ;
    else
		temp = temp + L"对象使用"
		+ (CString)key.Content_Encoding + L"加密\r\n";
    if (key.if_chunked)
		temp = temp + L"对象使用chunked加密传输\r\n";
	if (res_or_req == 0) {
		temp = temp + L"HTTP版本：" +
			(CString)key.http_version + L"\r\n"
			+ L"HTTP状态码：" + (CString)key.status + L"\r\n"
			+ L"HTTP修饰符：" + (CString)key.modifier + L"\r\n";
	}
	else {
		temp = temp + L"HTTP版本：" +
			(CString)key.http_version + L"\r\n"
			+ L"HTTP方法：" + (CString)key.method + L"\r\n"
			+ L"URL：" + (CString)key.URL + L"\r\n";
	}
	return temp;
}

int Request_reverter::save_head() {
	int i = 0;
    http_head_start = 14 + 20 + ppkt->tcp_header_length;
    http_body_start = 0;
    if (http_head_start < header->caplen) {
        // 将协议头部写入文件后按单词读取 
        content = (char*)malloc(header->caplen * sizeof(char));
        for (i = http_head_start; i < header->caplen; i++)
        {
            content[i - http_head_start] = pkt_data[i];
            //两个回车表示头部结束
            if (pkt_data[i] == '\r' && pkt_data[i + 1] == '\n' &&
                pkt_data[i + 2] == '\r' && pkt_data[i + 3] == '\n') {
                http_body_start = i + 4;
                content[i - http_head_start] = '\0';
                break;
            }
        }
        //判断是不是可读的HTTP头部
        if (strstr(content, "HTTP")) {
            ofstream outfile;
            try {
                outfile.open(save_path);
                outfile << content << endl;
                outfile << "------request http head-----" << endl;
                outfile.close();
            }
            catch (std::ios_base::failure& e) {
                std::cerr << e.what() << endl;
                cout << e.what() << endl;
                exit(1);
            }
			key.seq = ppkt->sequence;
			key.head_len = http_body_start-http_head_start;
			key.daddr = ppkt->daddr;
			key.saddr = ppkt->saddr;
			key.dport = ppkt->dport;
			key.sport = ppkt->sport;
            return 0;
        }
    }
    return 1;
}

int Request_reverter::http_head_parse() {
    strcpy(key.Content_Encoding, "\0");
    strcpy(key.Content_Length, "\0");
    strcpy(key.Content_Type, "\0");
    ifstream infile;
    try {
        infile.open(save_path);
        infile >> key.method;
        infile >> key.URL;
        infile >> key.http_version;

        char  tmp1[2000], tmp2[2000];
        while (infile >> tmp1) {
            int type = match_head(tmp1);
            if (type != 0 && type != 4) infile >> tmp2;
            switch (type) {
            case 1: strcpy(key.Content_Encoding, tmp2); break;
            case 2: strcpy(key.Content_Length, tmp2); break;
            case 3: strcpy(key.Content_Type, tmp2); break;
            case 4: key.if_chunked = 1; break;
            }
        }
        infile.close();
    }
    catch (std::ios_base::failure& e) {
        std::cerr << e.what() << endl;
        return -1;
    }
    if (strcmp(key.Content_Length, "\0") == 0) {
        return 1;
    }
    return 0;
}

int Respond_reverter::save_head() {
    int i = 0;
    key.seq = ppkt->sequence;
    http_head_start = 14 + 20 + ppkt->tcp_header_length;
    if (pkt_data[http_head_start] == 'H' && pkt_data[http_head_start + 1] == 'T'
        && pkt_data[http_head_start + 2] == 'T' && pkt_data[http_head_start + 3] == 'P')
    {
        /* 将协议头部写入文件后按单词读取 */
        content = (char*)malloc(header->caplen * sizeof(char));
        for (i = http_head_start; i < header->caplen; i++)
        {
            //两个回车表示头部结束
            if (pkt_data[i] == '\r' && pkt_data[i + 1] == '\n'
                && pkt_data[i + 2] == '\r' && pkt_data[i + 3] == '\n')
                break;
            printf("%c", pkt_data[i]);
            content[i - http_head_start] = pkt_data[i];
        }
        http_body_start = i + 4;
        content[i - http_head_start] = '\0';

        ofstream outfile;
        try {
            outfile.open(save_path);
            outfile << content << endl;
            outfile.close();
        }
        catch (std::ios_base::failure& e) {
            std::cerr << e.what() << endl;
            exit(1);
        }
		key.seq = ppkt->sequence;
		key.head_len = http_body_start - http_head_start;
		key.daddr = ppkt->daddr;
		key.saddr = ppkt->saddr;
		key.dport = ppkt->dport;
		key.sport = ppkt->sport;
        return 0;
    }
    else {
        return 1;
    }
}

int Respond_reverter::http_head_parse() {
    //初始化key中的值为0，是0表示http头部没有出现改值
    strcpy(key.Content_Encoding, "\0");
    strcpy(key.Content_Length, "\0");
    strcpy(key.Content_Type, "\0");
    ifstream infile;
    try {
        infile.open(save_path);
        infile >> key.http_version;
        infile >> key.status;
        infile >> key.modifier;
        if (strcmp(key.status, "200") != 0)
        {
            cout << "\nHTTP状态码不正确" << endl;
            cout << "错误的状态码是 " << key.status
                << " " << key.modifier << endl;
        }
		char  tmp1[2000], tmp2[2000];
        while (infile >> tmp1) {
            int type = match_head(tmp1);
            if (type != 0 && type != 4) infile >> tmp2;
            switch (type) {
            case 1: strcpy(key.Content_Encoding, tmp2); break;
            case 2: strcpy(key.Content_Length, tmp2); break;
            case 3: strcpy(key.Content_Type, tmp2); break;
            case 4: key.if_chunked = 1; break;
            }
        }
        infile.close();
    }
    catch (std::ios_base::failure& e) {
        std::cerr << e.what() << endl;
        exit(1);
    }
    if (strcmp(key.Content_Length, "\0") == 0) {
        return 1;
    }
    return 0;
}

int Http_reverter::match_head(char* s) {
    const struct key_mode mode;
    if (strcmp(s, mode.encoding) == 0)
        return 1;
    else if (strcmp(s, mode.length) == 0)
        return 2;
    else if (strcmp(s, mode.type) == 0)
        return 3;
    else if (strcmp(s, mode.chunked) == 0)
        return 4;
    else
        return 0;
}

int Http_reverter::http_handling(int& mark
    , struct key_word key_now
    , list<temp_mem>& body_list) {
    int type = 0, encoding = 0;
    if (key.Content_Type) {
        type = match_type(key_now.Content_Type);
        cout << key_now.Content_Type << endl;
    }
    else {
		MessageBox(GetForegroundWindow(), L"报错", L"还原http首部出错\n请退出重试", 1);
        exit(1);//1表示异常退出，0表示正常退出
    }
    if (strcmp(key.Content_Encoding, "\0")) {
        encoding = 1;
    }
	//跳过chunk的处理
	if (key_now.if_chunked) {
		mark = 0;
	}
    else {
        int start_seq = key_now.seq;
        int data_len = header->caplen - http_head_start;
        int head_len = http_body_start - http_head_start;
        //save_body(mark, type);
		struct temp_mem temp_node;
		temp_node.sequence = ppkt->sequence;
		temp_node.body = &pkt_data[http_body_start];
		body_list.push_back(temp_node);
		if (ppkt->sequence - start_seq +
			data_len - head_len < atoi(key_now.Content_Length)) {
			mark = 1;
		}
		else mark = 0;
    }
    return 0;
}

int Http_reverter::match_type(char* s) {
    if (strstr(s, "image"))
        return 1;
    else if (strstr(s, "application"))
        return 2;
    else if (strstr(s, "text"))
        return 3;
    else
        return 0;
}

/*
* type 1:image 2:application 3:text
*/
int Http_reverter::save_body(struct key_word key
	, list<temp_mem>& body_list) {
    //mark=0表示是数据包的开头，有http头部
    body_save_path = "body.data";
	ofstream outfile;
	try {
		outfile.open(body_save_path, ios::app);
		if (strcmp(key.Content_Encoding, "\0"))
			outfile << "文件被加密了 "
			<< key.Content_Encoding << endl;
		outfile << endl;
		outfile << "Date " << __DATE__ << endl;
		outfile << key.Content_Type << endl;
		outfile.close();
	}
	catch (std::ios_base::failure& e) {
		std::cerr << e.what() << endl;
		MessageBox(NULL, L"文件读写出错", L"报错", MB_OKCANCEL);
		exit(1);
	}
        
    try {
        if (atoi(key.Content_Type) == 1) {
            //保存图片的要使用二进制读写
            outfile.open(body_save_path, ios::app | ios::binary);
        }
        else {
            outfile.open(body_save_path, ios::app);
        }
		for (list<temp_mem>::iterator it = body_list.begin(); 
			it != body_list.end(); ++it) {
			outfile << it->body;
		}        
        outfile.close();
    }
    catch (std::ios_base::failure& e) {
        std::cerr << e.what() << endl;
		MessageBox(NULL, L"文件读写出错", L"报错", MB_OKCANCEL);
        exit(1);
    }

    return 0;
}

/* 这个按钮的处理函数完成交互分析功能 */
void menu::OnBnClickedButton4()
{
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	pcap_t* fp;
	pcap_dumper_t* dumpfile;
	char errbuf[PCAP_ERRBUF_SIZE];
	const char* path = "test.txt";
	char source[PCAP_BUF_SIZE];
	int res = 0;//记录数据包读取的情况，-1表示出错，0表示读取结束 

	/* 读取转存的数据包 */
	// 根据WinPcap语法创建源字符串 
	if (pcap_createsrcstr(source,         // variable that will keep the source string
		PCAP_SRC_FILE,  // we want to open a file
		NULL,           // remote host
		NULL,           // port on the remote host
		path,        // name of the file we want to open
		errbuf          // error buffer
	) != 0) {
		fprintf(stderr, "\nError creating a source string\n");
		MessageBox(L"转存文件路径错误");
		exit(1);
	}

	// 打开转存文件
	if ((fp = pcap_open(source,         // name of the device
		65536,          // portion of the packet to capture
						// 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode 混合模式
		1000,              // read timeout
		NULL,              // authentication on the remote machine
		errbuf         // error buffer
	)) == NULL) {
		fprintf(stderr, "\nUnable to open the file %s.\n", source);
		MessageBox(L"无法打开转存文件");
		exit(1);
	}

	int i = 0;
	CString temp;
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0 && i < 10)
	{
		i++;
		struct pkt_node pkt;
		struct pkt_node* ppkt;
		ppkt = &pkt;

		/* 识别HTTP协议 */
		Http_identifier identifier;
		identifier.init(header, pkt_data, ppkt);
		int ip_proto = 0;
		ip_proto = identifier.ip_parse();
		if (ip_proto == 6) identifier.tcp_parse();
		else {
			temp = temp + L"is not HTTP\r\n\r\n";
			continue;
		}
		if (ppkt->dport == 80) {
			temp = temp + L"request HTTP\r\n";
		}
		else if (ppkt->sport == 80) {
			temp = temp + L"respond HTTP\r\n";
		}
		else {
			temp = temp + L"is not HTTP\r\n\r\n";
			continue;
		}

		char* content = '\0';
		int http_head_start = 14 + 20 + ppkt->tcp_header_length;
		if (http_head_start < header->caplen) {
			/* 将协议头部写入文件后按单词读取 */
			content = (char*)malloc(header->caplen * sizeof(char));
			for (int j = http_head_start; j < header->caplen; j++)
			{
				content[j - http_head_start] = pkt_data[j];
				//两个回车表示头部结束
				if (pkt_data[j - 1] == '\r' && pkt_data[j] == '\n') {
					content[j - http_head_start + 1] = '\0';
					break;
				}
			}
			if (strstr(content, "HTTP")) {
				temp = temp + (CString)content;
			}
		}
		/* 分析交互功能 */
		if (ppkt->dport == 80) {
			temp = temp + L"客户端->服务器\r\n";
		}
		else {
			temp = temp + L"服务器->客户端\r\n";
		}

		struct tm ltime;
		char timestr[16];
		time_t local_tv_sec;

		// 把时间戳转换成可读的形式
		local_tv_sec = header->ts.tv_sec;
		localtime_s(&ltime, &local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
		wchar_t buf1[1000], buf2[1000];
		_itow((int)(header->len), buf1, 10);
		temp = temp + L"包捕获的时间：" + (CString)timestr
			+ L", 包的总长度：" + buf1 + L"\r\n";
		_itow((int)(ppkt->sport), buf1, 10);
		_itow((int)(ppkt->dport), buf2, 10);
		temp = temp + L"源端口：" + buf1 + L" ->目的端口："
			+ buf2 + L"\r\n";

		temp = temp + L"TCP标志："
			+ CString((ppkt->tcp_flag).c_str()) + L"\r\n";
		_itow((int)(ppkt->sequence), buf1, 10);
		_itow((int)(ppkt->tcp_header_length), buf2, 10);
		temp = temp + L"TCP的字节流序号：" + buf1 + L"\r\n";
		temp = temp + L"TCP的首部长度：" + buf2 + L"\r\n\r\n";
	}
	SetDlgItemText(IDC_EDIT1, temp);
}

void menu::OnBnClickedButton5()
{
	SetDlgItemText(IDC_EDIT3, L"还原请求协议请输入1，应答协议请输入0");
}

/* 这个按钮的处理函数完成协议还原功能 */
void menu::OnBnClickedButton1()
{
	int res_or_req;//还原的是请求协议1还是应答协议0
	CString sq;
	GetDlgItemText(IDC_EDIT3, sq);
	res_or_req = atoi((LPSTR)(LPCTSTR)sq);
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	pcap_t* fp;
	pcap_dumper_t* dumpfile;
	char errbuf[PCAP_ERRBUF_SIZE];
	const char* path = "test.txt";
	char source[PCAP_BUF_SIZE];
	int res = 0;//记录数据包读取的情况，-1表示出错，0表示读取结束 

	/* 读取转存的数据包 */
	// 根据WinPcap语法创建源字符串 
	if (pcap_createsrcstr(source,         // variable that will keep the source string
		PCAP_SRC_FILE,  // we want to open a file
		NULL,           // remote host
		NULL,           // port on the remote host
		path,        // name of the file we want to open
		errbuf          // error buffer
	) != 0) {
		fprintf(stderr, "\nError creating a source string\n");
		MessageBox(L"转存文件路径错误");
		exit(1);
	}
	 
	// 打开转存的文件
	if ((fp = pcap_open(source,         // name of the device
		65536,          // portion of the packet to capture
						// 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode 混合模式
		1000,              // read timeout
		NULL,              // authentication on the remote machine
		errbuf         // error buffer
	)) == NULL) {
		fprintf(stderr, "\nUnable to open the file %s.\n", source);
		MessageBox(L"无法打开转存文件");
		exit(1);
	}

	int mark = 0;
	int last_seq = 0;
	struct key_word key_now;	// 保存正在还原的协议的关键信息
	list<temp_mem> temp_list;	// 保存失序数据包的链表
	list<temp_mem> body_list;	// 保存顺序正确的数据包的链表
	CString temp;				//保存要显示到对话框中的内容

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		struct pkt_node pkt;
		struct pkt_node* ppkt;
		ppkt = &pkt;

		/* 识别HTTP协议 */
		Http_identifier identifier;
		identifier.init(header, pkt_data, ppkt);
		int ip_proto = 0;
		ip_proto = identifier.ip_parse();
		if (ip_proto == 6) identifier.tcp_parse();
		else {
			temp = temp + L"is not HTTP\r\n";
			continue;
		}
		if (ppkt->dport == 80) {
			temp = temp + L"request HTTP\r\n";
		}
		else if (ppkt->sport == 80) {
			temp = temp + L"respond HTTP\r\n";
		}
		else {
			temp = temp + L"is not HTTP\r\n";
			continue;
		}

		/* HTTP协议还原 */
		if (!(ppkt->dport == 80 && res_or_req == 1)
			&& !(ppkt->sport == 80 && res_or_req == 0))
			continue;
		Http_reverter* preverter = NULL;
		int ret = 0;//记录函数的返回值
		char* head_save_path = "\0";
		//request http
		if (ppkt->dport == 80 && res_or_req == 1) {
			Request_reverter reverter;
			preverter = &reverter;
			head_save_path = "request_head.txt";
		}
		//respond http
		if (ppkt->sport == 80 && res_or_req == 0) {
			Respond_reverter reverter;
			head_save_path = "respond_head.txt";
			preverter = &reverter;						
		}

		/* 数据包重组 */
		preverter->init(header, pkt_data, ppkt, head_save_path);
		//ret=0表示有http头部，1表示没有
		ret = preverter->save_head();
		//有http头，表示是新数据的开头
		//设置mark，start_seq, key和length
		if (ret == 0) {
			//出现乱序，该数据包不属于本协议，跳过本轮
			if (mark) {
				mark = 0;
				continue;
			}
			else {
				//返回1表示没有body，0表示有body，-1表示读写出错
				ret = preverter->http_head_parse();
				if (ret == 1) {
					//没有body，不用保存body，继续下一轮
					mark = 0;
					key_now = preverter->key;
					temp = temp + L"该HTTP协议没有实体部分\r\n";
					
					temp = temp + preverter->show_info(key_now, res_or_req);
					SetDlgItemText(IDC_EDIT1, temp);
					MessageBox(L"还原结束");
					break;
				}
				else {
					//有body，把还原中需要的信息记录到key_now中
					last_seq = ppkt->sequence;
					key_now = preverter->key;
					preverter->http_handling(mark, key_now,body_list);
				}
			}
		}
		else if (ret == 1 && mark == 1) {
			int diff = ppkt->sequence - last_seq;
			if (ppkt->daddr == key_now.daddr &&
				ppkt->saddr == key_now.saddr) {
				if (diff <= 1460 && diff > 0) {
					//顺序正确
					preverter->http_body_start = preverter->http_head_start;
					preverter->http_handling(mark, key_now,body_list);
					last_seq = ppkt->sequence;
				}
				else {
					// 属于本协议的乱序数据包，暂存处理						
					mark = 0;
					// continue;
					// 为乱序数据包创建结点，存放到链表中
					struct temp_mem temp_node;
					temp_node.sequence = ppkt->sequence;
					temp_node.body = &pkt_data[preverter->http_body_start];
					temp_list.push_back(temp_node);
					// 在暂存链表中寻找是否有顺序正确的节点
					for (list<temp_mem>::iterator it = temp_list.begin();
						it != temp_list.end(); ) {
						if (it->sequence - last_seq <= 1460
							&& it->sequence - last_seq > 0) {
							body_list.push_back(*it);
							temp_list.erase(it);
						}
						else it++;
					} 
				}
			}
			else {
				//不属于本协议，跳过
				mark = 0;
				continue;
			}
			//mark_res从1变成0说明还原完成
			if (mark == 0) {
				//将链表中保存的数据写入文件
				preverter->save_body(key_now, body_list);
				temp = temp + preverter->show_info(key_now, res_or_req);
				SetDlgItemText(IDC_EDIT1, temp);
				MessageBox(L"还原结束");
				break;
			}
		}
	}
	if (mark) {
		temp = temp + L"已还原部分内容，由于您设置的抓包数量较少，未能重组出完整的分组\r\n"
			+ L"可增大抓包的数量再重试哟~\r\n";
		SetDlgItemText(IDC_EDIT1, temp);
		MessageBox(L"还原结束");
	}

	if (res == -1) {
		MessageBox(L"在读取转存数据包的文件时发生错误" + (CString)(pcap_geterr(fp)));
		exit(1);
	}
}
