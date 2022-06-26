
// MFCApplication2Dlg.h: 头文件
//

#pragma once
#include "pcap.h"
#include "menu.h"

// CMFCApplication2Dlg 对话框
class CMFCApplication2Dlg : public CDialogEx
{
// 构造
public:
	CMFCApplication2Dlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFCAPPLICATION2_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	// 展示设备列表
	CEdit dlist;
	// 用户选择的设备
	CEdit adapter;
	afx_msg void OnBnClickedButton2();
	
	double dur;
	pcap_if_t* d;
	pcap_t* adhandle;
	pcap_dumper_t* dumpfile;
	pcap_if_t* alldevs;
	// 是否使用过滤器
	CEdit isfilter;
	afx_msg void OnBnClickedButton3();
};

void packet_save(u_char* dumpfile,
	const struct pcap_pkthdr* header, const u_char* pkt_data);
