
/**********Ӧ�ó��������ͨ����صĺ궨��*************/
//���Ӧ�ó������ĵȴ��¼�
#define	IOCTL_UserEvent \
CTL_CODE(FILE_DEVICE_UNKNOWN,0x201,METHOD_NEITHER,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//���乲��������Ӧ�ó�����ͨ��
#define	IOCTL_GetShareMemory \
CTL_CODE(FILE_DEVICE_UNKNOWN,0x202,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//֪ͨ������ǲ���
#define	IOCTL_VirusSet	\
CTL_CODE(FILE_DEVICE_UNKNOWN,0x203,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//֪ͨ����ȡ����ǲ���
#define	IOCTL_VirusUnset	\
CTL_CODE(FILE_DEVICE_UNKNOWN,0x205,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//��������������¼��Ĳ�����Ϣ��������־���������
#define	IOCTL_VirusShow	\
CTL_CODE(FILE_DEVICE_UNKNOWN,0x204,METHOD_NEITHER,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//֪ͨ�����Ƿ���˶�����
#define	IOCTL_ReadControl	\
CTL_CODE(FILE_DEVICE_UNKNOWN,0x206,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//֪ͨ�����Ƿ����д����	
#define	IOCTL_WriteControl	\
CTL_CODE(FILE_DEVICE_UNKNOWN,0x207,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//֪ͨ�����Ƿ���������ļ�������
#define	IOCTL_SetFileControl	\
CTL_CODE(FILE_DEVICE_UNKNOWN,0x208,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//��ʾ����ȫ�ֹ�����
#define	IOCTL_ShowControl	\
CTL_CODE(FILE_DEVICE_UNKNOWN,0x209,METHOD_NEITHER,FILE_READ_ACCESS | FILE_WRITE_ACCESS)
/******************************************************/


typedef	struct _ClientLog
{
	ULONG	CharCounts;	//������־���ַ�����
	WCHAR	LogBuffer[];//������
}CLIENT_LOG , *PCLIENT_LOG;

typedef	struct _Log
{
	ULONG	CharCounts;	//��־���ַ�����
	WCHAR	Buffer[2048];//��־������
}LOG , *PLOG;