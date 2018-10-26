#include	<Windows.h>
#include "resource.h"
#include "FsProtectClient.h"
#include	<Richedit.h>

//全局变量
HWND	hMainDlg;	//对话框句柄
PCLIENT_LOG	g_pClientLog = NULL;//日志缓冲区
HANDLE	g_hDriver;	//驱动控制设备句柄
HANDLE	g_hEvent = NULL;	//事件对象句柄
HANDLE	g_hThread = NULL;	//线程句柄
LOG	g_Log = { 0 };	//日志缓冲区


/*该函数用来在字符串中统计起始位置的空格数量
参数:
pStirng指向要检查的宽字符串
*/
ULONG	_StringSkipSpace(
	IN	PWCHAR	_pString 
)
{
	ULONG	SpaceCount = 0;

	for (;;)
	{
		if (wcsnicmp(
			(_pString + SpaceCount),
			L" " ,
			1 ) == 0)
		{	//是空格就增加计数
			SpaceCount++;
		}
		else
			return SpaceCount;	//不是空格就退出并返回起始位置空格的数量
	}
}


//日志线程
VOID	_LogThread(
	IN	DWORD	_Context
)
{
	SCROLLINFO	ScrollInfor;
	HANDLE	hLogText;	//日志文本框的句柄

	//初始滚动条结构体
	ScrollInfor.cbSize = sizeof( ScrollInfor );
	ScrollInfor.fMask = SIF_POS | SIF_RANGE | SIF_PAGE;

	//获得文本编辑框句柄
	hLogText = GetDlgItem(
		hMainDlg ,
		IDC_LOG );

	for (;;)
	{
		//等待事件
		WaitForSingleObject(
			g_hEvent ,
			INFINITE );
		
		//重新设置事件为未触发
		ResetEvent( g_hEvent );

		//将日志输出到文本框
		
		if ((g_Log.CharCounts  + g_pClientLog->CharCounts) > sizeof( g_Log.Buffer )/sizeof(WCHAR))
		{
			//缓冲区字符快满了就清空一次
			ZeroMemory( g_Log.Buffer , sizeof( g_Log.Buffer ) );
			g_Log.CharCounts = 0;
		}

		wcsncat(
			&g_Log.Buffer[g_Log.CharCounts] ,
			g_pClientLog->LogBuffer ,
			g_pClientLog->CharCounts );
		
		SetDlgItemTextW(
			hMainDlg ,
			IDC_LOG ,
			g_Log.Buffer );
		
		
		//设置滚动条显示最下面文本
		GetScrollInfo(
			hLogText ,
			SB_VERT ,
			&ScrollInfor );

		ScrollInfor.nPos =
			ScrollInfor.nMax - ScrollInfor.nPage +1;

		SetScrollInfo(
			hLogText ,
			SB_VERT ,
			&ScrollInfor ,
			TRUE );


		g_Log.CharCounts += g_pClientLog->CharCounts ;
	}
}

INT_PTR CALLBACK _DlgProc( HWND hDlg , UINT message , WPARAM wParam , LPARAM lParam )
{
	BOOL Result;
	DWORD	dwRet;

	switch (message)
	{
		case WM_INITDIALOG:

			hMainDlg = hDlg;

			//打开驱动的控制设备
			g_hDriver = CreateFileW(
				L"\\\\.\\PowerfulGun_FsProtect" ,
				GENERIC_WRITE | GENERIC_READ ,
				FILE_SHARE_READ ,
				NULL ,
				OPEN_EXISTING ,
				FILE_ATTRIBUTE_NORMAL ,
				NULL );
			if (g_hDriver == INVALID_HANDLE_VALUE)
			{
				//驱动未加载
				SetDlgItemTextW(
					hDlg ,
					IDC_LOG ,
					L"The FsProtect Driver not load !\n" );
				//设置命令框为不可输入状态
				EnableWindow(
					GetDlgItem( hDlg , IDC_CMD ) ,
					FALSE );
				return 0;
			}
			//驱动已经加载
			SetDlgItemTextW(
				hDlg ,
				IDC_MODLOG ,
				L"FsProtect.sys\n" );

			//将事件对象发送给驱动的控制设备
			Result = DeviceIoControl(
				g_hDriver ,
				IOCTL_UserEvent ,
				&g_hEvent ,
				sizeof( PHANDLE ) ,
				NULL ,
				0 ,
				&dwRet ,
				NULL );
			if (Result == FALSE)
			{
				SetDlgItemTextW(
					hDlg ,
					IDC_LOG ,
					L"Fail to send user event to driver !\n" );
				return	0;
			}

			//获得共享缓冲区地址
			Result = DeviceIoControl(
				g_hDriver ,
				IOCTL_GetShareMemory ,
				NULL ,
				0 ,
				&g_pClientLog ,
				sizeof( PCLIENT_LOG ) ,
				&dwRet ,
				NULL );
			if (Result == FALSE)
			{
				SetDlgItemTextW(
					hDlg ,
					IDC_LOG ,
					L"Fail to get shared address !\n" );
				return	0;
			}

			//开启线程等待事件
			g_hThread = CreateThread(
				NULL ,
				0 ,
				_LogThread ,
				NULL ,
				0 ,
				NULL );


			return (INT_PTR)TRUE;

		case WM_COMMAND:
			{
				if (LOWORD( wParam ) == IDOK)
				{
					WCHAR	CmdBuffer[256];
					ULONG	StringPos = 0;

					GetDlgItemText(
						hDlg ,
						IDC_CMD ,
						CmdBuffer ,
						sizeof( CmdBuffer ) );

					//分析命令
					if (wcsnicmp(
						CmdBuffer ,
						L"?" ,
						wcslen( L"?" ) ) == 0)	//?
					{
						SetDlgItemText(
							hDlg ,
							IDC_LOG ,
							L"You Can Use:\r\n\
clear --clear log output\r\n\
virus set XXX --use name XXX to tag a virus\r\n\
virus unset X --use number of virus to untag this virus\r\n\
virus show --show information of VirusList\r\n\
filter set read --let the driver to check IRP_MJ_READ request\r\n\
filter unset read --don\'t let the driver to check IRP_MJ_READ request\r\n\
filter set write --let the driver to check IRP_MJ_WRITE request\r\n\
filter unset write --don\'t let the driver to check IRP_MJ_WRITE request\r\n\
filter set setfile --let the driver to check IRP_MJ_SET_INFORMATION request\r\n\
filter unset setfile --dont\'t let the driver to check IRP_MJ_SET_INFORMATION request\r\n" );
						goto	CLEAR_INPUT;
					}
					else if (wcsnicmp(
						CmdBuffer ,
						L"clear" ,
						wcslen( L"clear" ) ) == 0)	//clear
					{
						SetDlgItemText(
							hDlg ,
							IDC_LOG ,
							L"" );
						g_Log.CharCounts = 0;
						goto	CLEAR_INPUT;
					}
					else if (wcsnicmp(
						CmdBuffer ,
						L"virus" ,
						wcslen( L"virus" ) ) == 0)	//virus
					{
						StringPos += wcslen( L"virus" );//递进

						//跳过空格
						StringPos += _StringSkipSpace(&CmdBuffer[StringPos] );
						//for (;;)
						//{
						//	if (wcsnicmp(
						//		&CmdBuffer[StringPos] ,
						//		L" " ,
						//		1 ) == 0)
						//	{	//是空格就跳过
						//		StringPos += 1;
						//	}
						//	else
						//		break;	//不是空格就退出循环
						//}

						//继续比较字符串,查找命令字符串
						if (wcsnicmp(
							&CmdBuffer[StringPos] ,
							L"show" ,
							wcslen( L"show" ) ) == 0)
						{
							Result = DeviceIoControl(
								g_hDriver ,
								IOCTL_VirusShow ,
								NULL , 0 , NULL , 0 ,
								&dwRet , NULL );
							if (!Result)
							{
								SetDlgItemText(
									hDlg ,
									IDC_LOG ,
									L"Virus Show Fail!\r\n" );
								goto CLEAR_INPUT;
							}
						} // if (virus show)
						else if (wcsnicmp(
							&CmdBuffer[StringPos] ,
							L"set" ,
							wcslen( L"set" ) ) == 0)	// virus set
						{
							StringPos += wcslen( L"set" );	//递进
							//跳过空格
							StringPos +=
								_StringSkipSpace( &CmdBuffer[StringPos] );
							//for (;;)
							//{
							//	if (wcsnicmp(
							//		&CmdBuffer[StringPos] ,
							//		L" " ,
							//		1 ) == 0)
							//	{	//是空格就跳过
							//		StringPos += 1;
							//	}
							//	else
							//		break;	//不是空格就退出循环
							//}
							//如果之后没有字符串就报错,一定要指定名称
							if (wcsnicmp(
								&CmdBuffer[StringPos] ,
								L"" ,
								1 ) == 0)
							{
								SetDlgItemText(
									hDlg ,
									IDC_LOG ,
									L"Virus Set Fail !--- Must has an name!\r\n" );
								return;
							}
							//如果指定的名称太长也会报错
							if (wcslen( &CmdBuffer[StringPos] ) >= 32)
							{
								SetDlgItemText(
									hDlg ,
									IDC_LOG ,
									L"Virus Set Fail !--- Name too long!\r\n" );
								return;
							}

							PWCHAR	pVirusName = &CmdBuffer[StringPos];	//指向病毒名称

							Result = DeviceIoControl(
								g_hDriver ,
								IOCTL_VirusSet ,
								pVirusName ,
								sizeof( WCHAR ) * (wcslen( pVirusName )+1) ,
								NULL ,
								0 , &dwRet , NULL );	//一定要有dwRet参数
							if (Result)
							{
								SetDlgItemText(
									hDlg ,
									IDC_LOG ,
									L"Virus Set Success !\r\n" );
								goto	CLEAR_INPUT;
							}

						} //  if(virus set)
						else if (wcsnicmp(
							&CmdBuffer[StringPos] ,
							L"unset" ,
							wcslen( L"unset" ) ) == 0)	//virus unset
						{
							StringPos += wcslen( L"unset" );	//递进

							//跳过空格
							StringPos +=
								_StringSkipSpace( &CmdBuffer[StringPos] );
							//for (;;)
							//{
							//	if (wcsnicmp(
							//		&CmdBuffer[StringPos] ,
							//		L" " ,
							//		1 ) == 0)
							//	{	//是空格就跳过
							//		StringPos += 1;
							//	}
							//	else
							//		break;	//不是空格就退出循环
							//}
							//如果之后没有字符串就报错,一定要指定unset的病毒编号Number
							if (wcsnicmp(
								&CmdBuffer[StringPos] ,
								L"" ,
								1 ) == 0)
							{
								SetDlgItemText(
									hDlg ,
									IDC_LOG ,
									L"Virus Unset Fail !--- Must has an number!\r\n" );
								return;
							}
							//测试之后的字符串是否为数字
							INT	Number;
							PWCHAR	pStrEnd = NULL;
							Number = wcstoul(
								&CmdBuffer[StringPos] ,
								&pStrEnd , 10 );
							if (*pStrEnd != L'\0' || Number < 0)
							{
								SetDlgItemText(
									hDlg ,
									IDC_LOG ,
									L"Virus Unset Fail !--- Unexpect Number!\r\n" );
								return;
							}
							else
							{
								Result = DeviceIoControl(
									g_hDriver ,
									IOCTL_VirusUnset ,
									&Number ,
									sizeof( Number ) ,
									NULL , 0 ,
									&dwRet , NULL );
								if (Result)
								{
									SetDlgItemText(
										hDlg ,
										IDC_LOG ,
										L"Virus Unset success!\r\n" );
									goto	CLEAR_INPUT;
								}
							}


						} // if(virus unset)
						else
							goto	UNKNOWN_CMD;	// virus 下未知命令


					} //  if (virus)
					else if (wcsnicmp(
						CmdBuffer ,
						L"filter" ,
						wcslen( L"filter" ) ) == 0)	//filter
					{
						BOOLEAN	Control;
						StringPos += wcslen( L"filter" );//递进

						//跳过空格
						StringPos += _StringSkipSpace( &CmdBuffer[StringPos] );

						if (wcsnicmp(
							&CmdBuffer[StringPos] ,
							L"set" ,
							wcslen( L"set" ) ) == 0)	//filter set
						{
							StringPos += wcslen( L"set" );//递进

							//跳过空格
							StringPos += _StringSkipSpace( &CmdBuffer[StringPos] );
							if (wcsnicmp(
								&CmdBuffer[StringPos] ,
								L"read" ,
								wcslen( L"read" ) ) == 0)	//filter set read
							{
								StringPos += wcslen( L"read" );//递进

															  //跳过空格
								StringPos += _StringSkipSpace( &CmdBuffer[StringPos] );

								Control = TRUE;
								Result = DeviceIoControl(
									g_hDriver ,
									IOCTL_ReadControl ,
									&Control , sizeof( Control ) ,
									NULL , 0 ,
									&dwRet , NULL );
								if (Result)
								{
									SetDlgItemText(
										hDlg ,
										IDC_LOG ,
										L"filter set read success !\r\n" );
									goto	CLEAR_INPUT;
								}
							}
							else if (wcsnicmp(
								&CmdBuffer[StringPos] ,
								L"write" ,
								wcslen( L"write" ) ) == 0)	//filter set write
							{
								StringPos += wcslen( L"write" );//递进

															   //跳过空格
								StringPos += _StringSkipSpace( &CmdBuffer[StringPos] );

								Control = TRUE;
								Result = DeviceIoControl(
									g_hDriver ,
									IOCTL_WriteControl ,
									&Control , sizeof( Control ) ,
									NULL , 0 ,
									&dwRet , NULL );
								if (Result)
								{
									SetDlgItemText(
										hDlg ,
										IDC_LOG ,
										L"filter set write success !\r\n" );
									goto	CLEAR_INPUT;
								}
							}
							else if (wcsnicmp(
								&CmdBuffer[StringPos] ,
								L"setfile" ,
								wcslen( L"setfile" ) ) == 0)	//filter set setfile
							{
								StringPos += wcslen( L"setfile" );//递进

															   //跳过空格
								StringPos += _StringSkipSpace( &CmdBuffer[StringPos] );

								Control = TRUE;
								Result = DeviceIoControl(
									g_hDriver ,
									IOCTL_SetFileControl ,
									&Control , sizeof( Control ) ,
									NULL , 0 ,
									&dwRet , NULL );
								if (Result)
								{
									SetDlgItemText(
										hDlg ,
										IDC_LOG ,
										L"filter set setfile success !\r\n" );
									goto	CLEAR_INPUT;
								}
							}
							else
								goto	UNKNOWN_CMD;	//filter set 下未知命令
						}
						else if (wcsnicmp(
							&CmdBuffer[StringPos] ,
							L"unset" ,
							wcslen( L"unset" ) ) == 0)	//filter unset
						{
							StringPos += wcslen( L"unset" );//递进

							//跳过空格
							StringPos += _StringSkipSpace( &CmdBuffer[StringPos] );
							if (wcsnicmp(
								&CmdBuffer[StringPos] ,
								L"read" ,
								wcslen( L"read" ) ) == 0)	//filter unset read
							{
								StringPos += wcslen( L"read" );//递进

															   //跳过空格
								StringPos += _StringSkipSpace( &CmdBuffer[StringPos] );

								Control = FALSE;
								Result = DeviceIoControl(
									g_hDriver ,
									IOCTL_ReadControl ,
									&Control , sizeof( Control ) ,
									NULL , 0 ,
									&dwRet , NULL );
								if (Result)
								{
									SetDlgItemText(
										hDlg ,
										IDC_LOG ,
										L"filter unset read success !\r\n" );
									goto	CLEAR_INPUT;
								}
							}
							else if (wcsnicmp(
								&CmdBuffer[StringPos] ,
								L"write" ,
								wcslen( L"write" ) ) == 0)	//filter unset write
							{
								StringPos += wcslen( L"write" );//递进

															   //跳过空格
								StringPos += _StringSkipSpace( &CmdBuffer[StringPos] );

								Control = FALSE;
								Result = DeviceIoControl(
									g_hDriver ,
									IOCTL_WriteControl ,
									&Control , sizeof( Control ) ,
									NULL , 0 ,
									&dwRet , NULL );
								if (Result)
								{
									SetDlgItemText(
										hDlg ,
										IDC_LOG ,
										L"filter unset write success !\r\n" );
									goto	CLEAR_INPUT;
								}
							}
							else if (wcsnicmp(
								&CmdBuffer[StringPos] ,
								L"setfile" ,
								wcslen( L"setfile" ) ) == 0)	//filter unset setfile
							{
								StringPos += wcslen( L"setfile" );//递进

															   //跳过空格
								StringPos += _StringSkipSpace( &CmdBuffer[StringPos] );

								Control = FALSE;
								Result = DeviceIoControl(
									g_hDriver ,
									IOCTL_SetFileControl ,
									&Control , sizeof( Control ) ,
									NULL , 0 ,
									&dwRet , NULL );
								if (Result)
								{
									SetDlgItemText(
										hDlg ,
										IDC_LOG ,
										L"filter unset setfile success !\r\n" );
									goto	CLEAR_INPUT;
								}
							}
							else
								goto	UNKNOWN_CMD;	//filter unset 下未知命令
						}
						else if (wcsnicmp(
							&CmdBuffer[StringPos] ,
							L"show" ,
							wcslen( L"show" ) ) == 0)	//filter show
						{
							DeviceIoControl(
								g_hDriver ,
								IOCTL_ShowControl ,
								NULL , 0 ,
								NULL , 0 ,
								&dwRet , NULL );
							goto	CLEAR_INPUT;
						}
						else
							goto	UNKNOWN_CMD;	//filter下未知命令

					} // if(filter)

				UNKNOWN_CMD:
						//未识别的命令
					SetDlgItemText(
						hDlg ,
						IDC_LOG ,
						L"Unknown Commander,use '?' for help\r\n" );

				CLEAR_INPUT:
						//输入正确的命令最后都会清空cmd文本框
					SetDlgItemText(
						hDlg ,
						IDC_CMD ,
						L"" );
					return (INT_PTR)TRUE;
				}
				break;
			}
		case WM_CLOSE:

			CloseHandle( g_hDriver );

			TerminateThread( g_hThread , 0 );
			EndDialog( hDlg , 0 );
			
	}
	return (INT_PTR)FALSE;
}


int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);


	g_hEvent = OpenEvent(
		EVENT_ALL_ACCESS ,
		FALSE ,
		L"PowerfulGun_FsProtectClient" );
	if (g_hEvent)
	{
		MessageBoxW(
			NULL ,
			L"The client is running !" ,
			L"Error",
			MB_ICONERROR );

		CloseHandle( g_hEvent );
		return	0;
	}

	g_hEvent = CreateEvent(
		NULL ,
		FALSE ,
		FALSE ,
		L"PowerfulGun_FsProtectClient" );
	if (g_hEvent == NULL)
	{
		MessageBoxW(
			NULL ,
			L"Fail to create event !" ,
			L"Error" ,
			MB_ICONERROR );
		return	0;
	}


	DialogBox( hInstance , MAKEINTRESOURCE( IDD_DIALOGBOX ) , NULL , _DlgProc );

	return	1;
}
