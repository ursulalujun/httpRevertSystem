
// MFCApplication2Dlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "MFCApplication2.h"
#include "MFCApplication2Dlg.h"
#include "afxdialogex.h"
#include "pcap.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMFCApplication2Dlg 对话框



CMFCApplication2Dlg::CMFCApplication2Dlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MFCAPPLICATION2_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCApplication2Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, dlist);
	DDX_Control(pDX, IDC_EDIT2, adapter);
	DDX_Control(pDX, IDC_EDIT3, isfilter);
}

BEGIN_MESSAGE_MAP(CMFCApplication2Dlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CMFCApplication2Dlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CMFCApplication2Dlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CMFCApplication2Dlg::OnBnClickedButton3)
END_MESSAGE_MAP()


// CMFCApplication2Dlg 消息处理程序

BOOL CMFCApplication2Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CMFCApplication2Dlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMFCApplication2Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMFCApplication2Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


/* 这个按钮的处理函数完成获取设备列表并打印 */ 
void CMFCApplication2Dlg::OnBnClickedButton1()
{
	
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* 选择设备 */
	// 拉取设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	// 打印设备列表
	for (d = alldevs; d; d = d->next)
	{
		char buf[10];
		_itoa(++i, buf, 10);
		CString device_info;
		GetDlgItemText(IDC_EDIT1, device_info);
		device_info = device_info + _T("\r\n") + (CString)buf 
			+ (CString)d->name + _T("\r\n") + (CString)d->description ;
		SetDlgItemText(IDC_EDIT1, device_info);

	}

	if (i == 0)
	{
		dlist.SetWindowTextW(L"\n没有查找到任何设备，请检查winPcap是否正确安装.\n");
		exit(1);
	}

}

/* 这个按钮的处理函数完成设备选择 */
void CMFCApplication2Dlg::OnBnClickedButton2()
{
	CString adapter;
	int i = 0;
	int inum;
	char errbuf[PCAP_ERRBUF_SIZE];
	GetDlgItemText(IDC_EDIT2, adapter);
	inum = atoi((LPSTR)(LPCTSTR)adapter);
	
	/* 打开适配器 */
	if (inum < 1 || inum > 4)
	{
		// 输入的编号超过了范围，释放当前列表，重新读取输入
		pcap_freealldevs(alldevs);
		MessageBox(L"输入出错了，请重启程序");
		exit(1);
	}

	// 跳转到被选则的设备
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	// 打开该设备
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
		MessageBox(L"无法打开网络适配器. WinPcap不支持该设备");
		pcap_freealldevs(alldevs);
		exit(1);
	}

}

void packet_save(u_char* dumpfile,
	const struct pcap_pkthdr* header, const u_char* pkt_data) {

	// 将数据包转存到dump文件中
	pcap_dump(dumpfile, header, pkt_data);

}

/* 这个按钮的处理函数完成过滤器的设置和抓包 */
void CMFCApplication2Dlg::OnBnClickedButton3()
{
	/* 设置过滤器 */
	CString use_filter;
	GetDlgItemText(IDC_EDIT3, use_filter);
	if (atoi((LPSTR)(LPCTSTR)use_filter)==0) {
		u_int netmask;
		char packet_filter[] = "tcp port 80";//若没有指定，默认dst or src
		struct bpf_program fcode;
		// 为了简化，链路层只支持DLT_EN10MB以太网 
		if (pcap_datalink(adhandle) != DLT_EN10MB)
		{
			fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
			MessageBox(L"以太网工作出现故障");
			exit(1);
		}

		if (d->addresses != NULL)
			// 检索接口的第一个地址的掩码
			netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
		else
			// 如果接口没有地址，就假设它C类网络中
			netmask = 0xffffff;

		// 编译过滤器
		if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
		{
			fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
			MessageBox(L"无法编译过滤器");
			exit(1);
		}

		// 设置过滤器 
		if (pcap_setfilter(adhandle, &fcode) < 0)
		{
			fprintf(stderr, "\nError setting the filter.\n");
			MessageBox(L"设置过滤器发送错误");
			exit(1);
		}
	}
	
	MessageBox(L"正在抓包中，请稍后...，抓包完成后会自动跳转");
	/* 捕获数据包 */
	const char* path = "test.txt";
	dumpfile = pcap_dump_open(adhandle, path);
	/* 抓包+转存*/
	pcap_loop(adhandle, 80, packet_save, (unsigned char*)dumpfile);

	menu page; //创建了一个新对话框类
	page.DoModal();  //加载新对话框
}



