
// InjectDllToolDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "InjectDllTool.h"
#include "InjectDllToolDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CInjectDllToolDlg 对话框




CInjectDllToolDlg::CInjectDllToolDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CInjectDllToolDlg::IDD, pParent)
	, m_uiExePath(_T(""))
	, m_uiDllPath(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CInjectDllToolDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT1, m_uiExePath);
	DDX_Text(pDX, IDC_EDIT2, m_uiDllPath);
}

BEGIN_MESSAGE_MAP(CInjectDllToolDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(ID_BTN_INJECT_DLL, &CInjectDllToolDlg::OnBnClickedBtnInjectDll)
	ON_BN_CLICKED(ID_BTN_UNINSTALL_DLL, &CInjectDllToolDlg::OnBnClickedBtnUninstallDll)
END_MESSAGE_MAP()


// CInjectDllToolDlg 消息处理程序

BOOL CInjectDllToolDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
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

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	CString path = CUtility::GetModulePath(NULL);
	m_uiDllPath = path + _T("IATHookTest.dll");
	m_uiExePath = _T("C:\\Windows\\explorer.exe");
	UpdateData(FALSE);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CInjectDllToolDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CInjectDllToolDlg::OnPaint()
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
HCURSOR CInjectDllToolDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CInjectDllToolDlg::OnBnClickedBtnInjectDll()
{
	UpdateData(TRUE);
	if(m_uiExePath.IsEmpty())
	{
		MessageBox(_T("请填写exe路径！"));
		return;
	}
	if(m_uiDllPath.IsEmpty())
	{
		MessageBox(_T("请填写dll路径！"));
		return;
	}
	CFileFind find;
	int ret = find.FindFile(m_uiExePath);
	if (ret == 0)
	{
		MessageBox(_T("exe文件不存在，请重新填写exe路径！"));
		return;
	}
	ret = find.FindFile(m_uiDllPath);
	if (ret == 0)
	{
		MessageBox(_T("dll文件不存在，请重新填写dll路径！"));
		return;
	}
	CUtility::InjectDllToExe(m_uiDllPath,m_uiExePath);
}


void CInjectDllToolDlg::OnBnClickedBtnUninstallDll()
{
	UpdateData(TRUE);
	if(m_uiExePath.IsEmpty())
	{
		MessageBox(_T("请填写exe路径！"));
		return;
	}
	if(m_uiDllPath.IsEmpty())
	{
		MessageBox(_T("请填写dll路径！"));
		return;
	}
	CFileFind find;
	int ret = find.FindFile(m_uiExePath);
	if (ret == 0)
	{
		MessageBox(_T("exe文件不存在，请重新填写exe路径！"));
		return;
	}
	ret = find.FindFile(m_uiDllPath);
	if (ret == 0)
	{
		MessageBox(_T("dll文件不存在，请重新填写dll路径！"));
		return;
	}
	CUtility::UninstallDllToExe(m_uiDllPath,m_uiExePath);
}
