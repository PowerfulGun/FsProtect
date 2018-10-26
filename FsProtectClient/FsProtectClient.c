// FsProtectClient.cpp : ����Ӧ�ó������ڵ㡣
//
#include	<Windows.h>
#include "resource.h"
#include "FsProtectClient.h"
#include	<Richedit.h>

//ȫ�ֱ���
HWND	hMainDlg;	//�Ի�����
PCLIENT_LOG	g_pClientLog = NULL;//��־������
HANDLE	g_hDriver;	//���������豸���
HANDLE	g_hEvent = NULL;	//�¼�������
HANDLE	g_hThread = NULL;	//�߳̾��
LOG	g_Log = { 0 };	//��־������


/*�ú����������ַ�����ͳ����ʼλ�õĿո�����
����:
pStirngָ��Ҫ���Ŀ��ַ���
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
		{	//�ǿո�����Ӽ���
			SpaceCount++;
		}
		else
			return SpaceCount;	//���ǿո���˳���������ʼλ�ÿո������
	}
}


//��־�߳�
VOID	_LogThread(
	IN	DWORD	_Context
)
{
	SCROLLINFO	ScrollInfor;
	HANDLE	hLogText;	//��־�ı���ľ��

	//��ʼ�������ṹ��
	ScrollInfor.cbSize = sizeof( ScrollInfor );
	ScrollInfor.fMask = SIF_POS | SIF_RANGE | SIF_PAGE;

	//����ı��༭����
	hLogText = GetDlgItem(
		hMainDlg ,
		IDC_LOG );

	for (;;)
	{
		//�ȴ��¼�
		WaitForSingleObject(
			g_hEvent ,
			INFINITE );
		
		//���������¼�Ϊδ����
		ResetEvent( g_hEvent );

		//����־������ı���
		
		if ((g_Log.CharCounts  + g_pClientLog->CharCounts) > sizeof( g_Log.Buffer )/sizeof(WCHAR))
		{
			//�������ַ������˾����һ��
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
		
		
		//���ù�������ʾ�������ı�
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

			//�������Ŀ����豸
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
				//����δ����
				SetDlgItemTextW(
					hDlg ,
					IDC_LOG ,
					L"The FsProtect Driver not load !\n" );
				//���������Ϊ��������״̬
				EnableWindow(
					GetDlgItem( hDlg , IDC_CMD ) ,
					FALSE );
				return 0;
			}
			//�����Ѿ�����
			SetDlgItemTextW(
				hDlg ,
				IDC_MODLOG ,
				L"FsProtect.sys\n" );

			//���¼������͸������Ŀ����豸
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

			//��ù���������ַ
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

			//�����̵߳ȴ��¼�
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

					//��������
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
						StringPos += wcslen( L"virus" );//�ݽ�

						//�����ո�
						StringPos += _StringSkipSpace(&CmdBuffer[StringPos] );
						//for (;;)
						//{
						//	if (wcsnicmp(
						//		&CmdBuffer[StringPos] ,
						//		L" " ,
						//		1 ) == 0)
						//	{	//�ǿո������
						//		StringPos += 1;
						//	}
						//	else
						//		break;	//���ǿո���˳�ѭ��
						//}

						//�����Ƚ��ַ���,���������ַ���
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
							StringPos += wcslen( L"set" );	//�ݽ�
							//�����ո�
							StringPos +=
								_StringSkipSpace( &CmdBuffer[StringPos] );
							//for (;;)
							//{
							//	if (wcsnicmp(
							//		&CmdBuffer[StringPos] ,
							//		L" " ,
							//		1 ) == 0)
							//	{	//�ǿո������
							//		StringPos += 1;
							//	}
							//	else
							//		break;	//���ǿո���˳�ѭ��
							//}
							//���֮��û���ַ����ͱ���,һ��Ҫָ������
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
							//���ָ��������̫��Ҳ�ᱨ��
							if (wcslen( &CmdBuffer[StringPos] ) >= 32)
							{
								SetDlgItemText(
									hDlg ,
									IDC_LOG ,
									L"Virus Set Fail !--- Name too long!\r\n" );
								return;
							}

							PWCHAR	pVirusName = &CmdBuffer[StringPos];	//ָ�򲡶�����

							Result = DeviceIoControl(
								g_hDriver ,
								IOCTL_VirusSet ,
								pVirusName ,
								sizeof( WCHAR ) * (wcslen( pVirusName )+1) ,
								NULL ,
								0 , &dwRet , NULL );	//һ��Ҫ��dwRet����
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
							StringPos += wcslen( L"unset" );	//�ݽ�

							//�����ո�
							StringPos +=
								_StringSkipSpace( &CmdBuffer[StringPos] );
							//for (;;)
							//{
							//	if (wcsnicmp(
							//		&CmdBuffer[StringPos] ,
							//		L" " ,
							//		1 ) == 0)
							//	{	//�ǿո������
							//		StringPos += 1;
							//	}
							//	else
							//		break;	//���ǿո���˳�ѭ��
							//}
							//���֮��û���ַ����ͱ���,һ��Ҫָ��unset�Ĳ������Number
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
							//����֮����ַ����Ƿ�Ϊ����
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
							goto	UNKNOWN_CMD;	// virus ��δ֪����


					} //  if (virus)
					else if (wcsnicmp(
						CmdBuffer ,
						L"filter" ,
						wcslen( L"filter" ) ) == 0)	//filter
					{
						BOOLEAN	Control;
						StringPos += wcslen( L"filter" );//�ݽ�

						//�����ո�
						StringPos += _StringSkipSpace( &CmdBuffer[StringPos] );

						if (wcsnicmp(
							&CmdBuffer[StringPos] ,
							L"set" ,
							wcslen( L"set" ) ) == 0)	//filter set
						{
							StringPos += wcslen( L"set" );//�ݽ�

							//�����ո�
							StringPos += _StringSkipSpace( &CmdBuffer[StringPos] );
							if (wcsnicmp(
								&CmdBuffer[StringPos] ,
								L"read" ,
								wcslen( L"read" ) ) == 0)	//filter set read
							{
								StringPos += wcslen( L"read" );//�ݽ�

															  //�����ո�
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
								StringPos += wcslen( L"write" );//�ݽ�

															   //�����ո�
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
								StringPos += wcslen( L"setfile" );//�ݽ�

															   //�����ո�
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
								goto	UNKNOWN_CMD;	//filter set ��δ֪����
						}
						else if (wcsnicmp(
							&CmdBuffer[StringPos] ,
							L"unset" ,
							wcslen( L"unset" ) ) == 0)	//filter unset
						{
							StringPos += wcslen( L"unset" );//�ݽ�

							//�����ո�
							StringPos += _StringSkipSpace( &CmdBuffer[StringPos] );
							if (wcsnicmp(
								&CmdBuffer[StringPos] ,
								L"read" ,
								wcslen( L"read" ) ) == 0)	//filter unset read
							{
								StringPos += wcslen( L"read" );//�ݽ�

															   //�����ո�
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
								StringPos += wcslen( L"write" );//�ݽ�

															   //�����ո�
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
								StringPos += wcslen( L"setfile" );//�ݽ�

															   //�����ո�
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
								goto	UNKNOWN_CMD;	//filter unset ��δ֪����
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
							goto	UNKNOWN_CMD;	//filter��δ֪����

					} // if(filter)

				UNKNOWN_CMD:
						//δʶ�������
					SetDlgItemText(
						hDlg ,
						IDC_LOG ,
						L"Unknown Commander,use '?' for help\r\n" );

				CLEAR_INPUT:
						//������ȷ��������󶼻����cmd�ı���
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
