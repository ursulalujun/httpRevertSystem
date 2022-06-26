#pragma once


// menu 对话框

class menu : public CDialogEx
{
	DECLARE_DYNAMIC(menu)

public:
	menu(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~menu();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG1 };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	// 展示交互过程
	CEdit danalysis;
	afx_msg void OnBnClickedButton4();
	// 选择还原请求还是应答协议
	afx_msg void OnBnClickedButton5();
	// 还原协议
	afx_msg void OnBnClickedButton1();
};
