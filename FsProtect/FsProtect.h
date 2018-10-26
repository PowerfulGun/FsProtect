#ifndef FSPROTECT_H
#define	FSPROTECT_H

#include	<ntifs.h>
#include	<ntdef.h>
#include	<ntddk.h>
#include	<ntdddisk.h>
#include	<wdmsec.h>
#include	<wchar.h>
#include	<intrin.h>


#define	POOL_TAG	'hqsb'

#define DELAY_ONE_MICROSECOND   (-10)
#define DELAY_ONE_MILLISECOND   (DELAY_ONE_MICROSECOND*1000)
#define DELAY_ONE_SECOND        (DELAY_ONE_MILLISECOND*1000)

#define FlagOn(_F,_SF)        ((_F) & (_SF))

#define SetFlag(_F,_SF)       ((_F) |= (_SF))

#define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))


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

// ��ʾ����ȫ�ֹ�����
#define	IOCTL_ShowControl	\
CTL_CODE(FILE_DEVICE_UNKNOWN,0x209,METHOD_NEITHER,FILE_READ_ACCESS | FILE_WRITE_ACCESS)
/******************************************************/


//
//  Macro to test if FAST_IO_DISPATCH handling routine is valid
//

#define VALID_FAST_IO_DISPATCH_HANDLER(_FastIoDispatchPtr, _FieldName) \
    (((_FastIoDispatchPtr) != NULL) && \
     (((_FastIoDispatchPtr)->SizeOfFastIoDispatch) >= \
            (FIELD_OFFSET(FAST_IO_DISPATCH, _FieldName) + sizeof(void *))) && \
     ((_FastIoDispatchPtr)->_FieldName != NULL))


//
// �����ж�һ���豸�����Ƿ��Ǳ��������������Ĺ����豸
// �Լ������Ĺ����豸���豸��չ�ж���Tag���
//
#define IS_MY_DEVICE_OBJECT(_devObj) \
    (((_devObj) != NULL) && \
     ((_devObj)->DriverObject == g_pFsFilterDriverObject) && \
      ((_devObj)->DeviceExtension != NULL) && \
	  ((*(ULONG *)(_devObj)->DeviceExtension) == POOL_TAG))

//
// �����ж�һ���豸�Ƿ��Ǳ����������Ŀ����豸
// �����豸û���豸��չ
//
#define IS_MY_CONTROL_DEVICE_OBJECT(_devObj) \
    (((_devObj) == g_pFsFilterControlDeviceObject) ? \
             TRUE : FALSE)

//
//	�꣺�ж��豸�����Ƿ��ǹ��ĵ��ļ�ϵͳ֮һ
//	���ĵ��ļ�ϵͳ�����������ļ�ϵͳ�����̺������ļ�ϵͳ
//
#define	IS_DESIRED_DEVICE_TYPE(_type)\
		(((_type) == FILE_DEVICE_DISK_FILE_SYSTEM) || \
		((_type) == FILE_DEVICE_CD_ROM_FILE_SYSTEM) || \
		((_type) == FILE_DEVICE_NETWORK_FILE_SYSTEM))

//
//  �꣺ͨ���豸���ͻ���豸���͵�asci�ַ���
//

#define GET_DEVICE_TYPE_NAME( _type ) \
            ((((_type) > 0) && ((_type) < (sizeof(DeviceTypeNames) / sizeof(PCHAR)))) ? \
                DeviceTypeNames[ (_type) ] : \
                "[Unknown]")
//
// ��֪�豸��������
//

static const PCHAR DeviceTypeNames[] = {
	"",
	"BEEP",
	"CD_ROM",
	"CD_ROM_FILE_SYSTEM",
	"CONTROLLER",
	"DATALINK",
	"DFS",
	"DISK",
	"DISK_FILE_SYSTEM",
	"FILE_SYSTEM",
	"INPORT_PORT",
	"KEYBOARD",
	"MAILSLOT",
	"MIDI_IN",
	"MIDI_OUT",
	"MOUSE",
	"MULTI_UNC_PROVIDER",
	"NAMED_PIPE",
	"NETWORK",
	"NETWORK_BROWSER",
	"NETWORK_FILE_SYSTEM",
	"NULL",
	"PARALLEL_PORT",
	"PHYSICAL_NETCARD",
	"PRINTER",
	"SCANNER",
	"SERIAL_MOUSE_PORT",
	"SERIAL_PORT",
	"SCREEN",
	"SOUND",
	"STREAMS",
	"TAPE",
	"TAPE_FILE_SYSTEM",
	"TRANSPORT",
	"UNKNOWN",
	"VIDEO",
	"VIRTUAL_DISK",
	"WAVE_IN",
	"WAVE_OUT",
	"8042_PORT",
	"NETWORK_REDIRECTOR",
	"BATTERY",
	"BUS_EXTENDER",
	"MODEM",
	"VDM",
	"MASS_STORAGE",
	"SMB",
	"KS",
	"CHANGER",
	"SMARTCARD",
	"ACPI",
	"DVD",
	"FULLSCREEN_VIDEO",
	"DFS_FILE_SYSTEM",
	"DFS_VOLUME",
	"SERENUM",
	"TERMSRV",
	"KSEC"
};


//����ȫ�ֹ��˿������ṹ��
typedef	struct _FILTER_CONTROL
{
	BOOLEAN	ReadControl;
	BOOLEAN	WriteControl;
	BOOLEAN	SetFileControl;
}FILTER_CONTROL , *PFILTER_CONTROL;


//�ļ����������豸��չ
typedef	struct _FSFILTER_DEIVCE_EXTENSION
{
	//��ʶ��������ʶ�Լ��������豸����
	ULONG	DeviceTag;

	//�󶨵��ļ�ϵͳ�豸
	PDEVICE_OBJECT	pLowerFsDeviceObject;

	//�ļ�ϵͳ��صĿ��豸������������ľ��豸
	PDEVICE_OBJECT	pStorageStackDeviceObject;

	//�������һ������ô���Ǵ��̾������������ǰ󶨵Ŀ����豸��
	UNICODE_STRING	DeviceName;
	//DeviceName�Ļ�����
	WCHAR	DeviceNameBuffer[64];
}FSFILTER_DEVICE_EXTENSION , *PFSFILTER_DEVICE_EXTENSION;


//��־������,�������ص�����־��Ϣ
typedef	struct _ClientLog
{
	ULONG	CharCounts;
	WCHAR	LogBuffer[];
}CLIENT_LOG , *PCLIENT_LOG;

//�����豸���豸��չ
typedef	struct _CONTROL_DEVICE_EXTENSION
{
	//�û��ȴ��¼�����
	PKEVENT	pUserEvent;
	//�û�������־����
	PCLIENT_LOG	pClientLog;
	//����������־�����MDL
	PMDL	pMdlLog;
	//ӳ��Ĺ����ַ
	PVOID	pSharedAddress;
}CONTROL_DEVICE_EXTENSION,*PCONTROL_DEVICE_EXTENSION;


//�ýṹ������������������Ϣ
typedef	struct _Virus
{
	WCHAR	Name[32];	//������
	WCHAR	ProcessName[32];	//��������ʹ�õĽ�����(��δʹ��)
	WCHAR	FileName[32];	//��������ʹ�õ��ļ���(��δʹ��)
	ULONG	FileData[4];	//������������
}VIRUS , *PVIRUS;

//�ýṹ���Ų�������Ϣ,��ʹ��˫����ṹ
typedef	struct _VirusList
{
	LIST_ENTRY	ListEntry;	//˫����ṹָ��
	ULONG	Number;	//��ǰ������˫����ṹ�еı��
	VIRUS	VirusInfor;	//����������Ϣ�Ľṹ��
}VIRUS_LIST,*PVIRUS_LIST;

//�ýṹ������������һ�η������ļ��������Ϣ
typedef struct _FileObjectContext
{
	PVOID	pFsContext;
	BOOLEAN		bIsVirus;
	ULONG	FileData[4];
}FILEOBJCONTEXT , *PFILEOBJCONTEXT;


//�ýṹ����������ļ���׺������Ϣ,������ļ�����ʱ���õ�
typedef struct _Suffix
{
	PWCHAR	pSuffix;
	ULONG	SuffixLength;
}SUFFIX , *PSUFFIX;


typedef   struct   _THREAD_BASIC_INFORMATION {   //   Information   Class   0   
	LONG           ExitStatus;
	PVOID         TebBaseAddress;
	CLIENT_ID   ClientId;
	LONG   AffinityMask;
	LONG   Priority;
	LONG   BasePriority;
}THREAD_BASIC_INFORMATION , *PTHREAD_BASIC_INFORMATION;


//����δ�����ĺ���
typedef NTSTATUS( *QUERY_INFO_THREAD ) (
	__in HANDLE ThreadHandle ,
	__in PROCESSINFOCLASS ThreadInformationClass ,
	__out PVOID ThreadInformation ,
	__in ULONG ThreadInformationLength ,
	__out_opt PULONG ReturnLength
	);
QUERY_INFO_THREAD ZwQueryInformationThread = NULL;

//����������
typedef	UINT64( __fastcall *ASM )();

CHAR ShellCode[] = "\x0F\x20\xC0\x81\xE0\xFF\xFF\xFE\xFF\x0F\x22\xC0\xC3";

//��������

VOID	_DriverUnload(
	IN	PDRIVER_OBJECT	_pDriverObject
);

BOOLEAN
_FastIoCheckIfPossible(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN ULONG Length ,
	IN BOOLEAN Wait ,
	IN ULONG LockKey ,
	IN BOOLEAN CheckForReadOperation ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
);

VOID
_FastIoDetachDevice(
	IN PDEVICE_OBJECT SourceDevice ,
	IN PDEVICE_OBJECT TargetDevice
);

BOOLEAN
_FastIoDeviceControl(
	IN PFILE_OBJECT FileObject ,
	IN BOOLEAN Wait ,
	IN PVOID InputBuffer OPTIONAL ,
	IN ULONG InputBufferLength ,
	OUT PVOID OutputBuffer OPTIONAL ,
	IN ULONG OutputBufferLength ,
	IN ULONG IoControlCode ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoLock(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN PLARGE_INTEGER Length ,
	PEPROCESS ProcessId ,
	ULONG Key ,
	BOOLEAN FailImmediately ,
	BOOLEAN ExclusiveLock ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoMdlRead(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN ULONG Length ,
	IN ULONG LockKey ,
	OUT PMDL *MdlChain ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoMdlReadComplete(
	IN PFILE_OBJECT FileObject ,
	IN PMDL MdlChain ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoMdlReadCompleteCompressed(
	IN PFILE_OBJECT FileObject ,
	IN PMDL MdlChain ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoMdlWriteComplete(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN PMDL MdlChain ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoMdlWriteCompleteCompressed(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN PMDL MdlChain ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoPrepareMdlWrite(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN ULONG Length ,
	IN ULONG LockKey ,
	OUT PMDL *MdlChain ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoQueryBasicInfo(
	IN PFILE_OBJECT FileObject ,
	IN BOOLEAN Wait ,
	OUT PFILE_BASIC_INFORMATION Buffer ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoQueryNetworkOpenInfo(
	IN PFILE_OBJECT FileObject ,
	IN BOOLEAN Wait ,
	OUT PFILE_NETWORK_OPEN_INFORMATION Buffer ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoQueryOpen(
	IN PIRP Irp ,
	OUT PFILE_NETWORK_OPEN_INFORMATION NetworkInformation ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoQueryStandardInfo(
	IN PFILE_OBJECT FileObject ,
	IN BOOLEAN Wait ,
	OUT PFILE_STANDARD_INFORMATION Buffer ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoRead(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN ULONG Length ,
	IN BOOLEAN Wait ,
	IN ULONG LockKey ,
	OUT PVOID Buffer ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoReadCompressed(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN ULONG Length ,
	IN ULONG LockKey ,
	OUT PVOID Buffer ,
	OUT PMDL *MdlChain ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	OUT struct _COMPRESSED_DATA_INFO *CompressedDataInfo ,
	IN ULONG CompressedDataInfoLength ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoUnlockAll(
	IN PFILE_OBJECT FileObject ,
	PEPROCESS ProcessId ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoUnlockAllByKey(
	IN PFILE_OBJECT FileObject ,
	PVOID ProcessId ,
	ULONG Key ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoUnlockSingle(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN PLARGE_INTEGER Length ,
	PEPROCESS ProcessId ,
	ULONG Key ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoWrite(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN ULONG Length ,
	IN BOOLEAN Wait ,
	IN ULONG LockKey ,
	IN PVOID Buffer ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
);

BOOLEAN
_FastIoWriteCompressed(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN ULONG Length ,
	IN ULONG LockKey ,
	IN PVOID Buffer ,
	OUT PMDL *MdlChain ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN struct _COMPRESSED_DATA_INFO *CompressedDataInfo ,
	IN ULONG CompressedDataInfoLength ,
	IN PDEVICE_OBJECT DeviceObject
);

VOID	_FsChangeCallback(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	BOOLEAN		_bFsActive
);

NTSTATUS	_FsFilterAttachToDeviceStack(
	IN	PDEVICE_OBJECT	_pSourceDevice ,
	IN	PDEVICE_OBJECT	_pTargetDevice ,
	IN OUT	PDEVICE_OBJECT*	_pLowerDevice
);

NTSTATUS	_FsFilterAttachToFsControlDevice(
	IN	PDEVICE_OBJECT	_pFsControlDevice ,
	IN	PUNICODE_STRING	_pDeviceName
);

NTSTATUS	_FsFilterAttachToMountedDevice(
	IN	PDEVICE_OBJECT	_pFsDeviceObject ,
	IN	PDEVICE_OBJECT	_pFilterDeviceObject
);

NTSTATUS	_FsFilterCloseDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
);

NTSTATUS	_FsFilterControlDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
);

NTSTATUS	_FsFilterControlMountVolume(
	IN	PDEVICE_OBJECT	_pFilterControlDevice ,
	IN	PIRP	_pIrp
);

NTSTATUS	_FsFilterCreateDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObjet ,
	IN	PIRP	_pIrp
);

NTSTATUS	_FsFilterDefaultDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
);

NTSTATUS	_FsFilterEnumrateFileSystemVolumes(
	IN	PDEVICE_OBJECT	_pFsControlDevice
);

NTSTATUS	_FsFilterFsControlCompletion(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp ,
	IN	PVOID	_pContext
);

NTSTATUS	_FsFilterFsControlMountVolumeComplete(
	//	IN	PDEVICE_OBJECT	_pFilterControlDevice ,
	IN	PIRP	_pIrp ,
	IN	PDEVICE_OBJECT	_pNewFilterDevice
);

VOID	_FsFilterGetBaseDeviceObjectName(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN OUT	PUNICODE_STRING	_pDeviceName
);

VOID	_FsFilterGetObjectName(
	IN	PVOID	_pObject ,
	IN OUT	PUNICODE_STRING	_pName
);

NTSTATUS	_FsFilterIsShadowCopyVolume(
	IN	PDEVICE_OBJECT	_pStorageStackDeviceObject ,
	OUT	PBOOLEAN	_pbIsShadowCopy
);

BOOLEAN	_FsIsAttachedToDevice(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	OUT OPTIONAL	PDEVICE_OBJECT* _ppAttachedDeviceObject
);

VOID	_FsFilterDetachFsControlDevice(
	IN	PDEVICE_OBJECT	_pFsControlDevice
);

NTSTATUS	_FsFilterControlLoadFileSystem(
	IN	PDEVICE_OBJECT	_pFilterDeviceObject ,
	IN	PIRP	_pIrp
);

NTSTATUS	_FsFilterFsControlLoadFileSystemComplete(
	IN	PDEVICE_OBJECT	_pFilterDeviceObject ,
	IN	PIRP	_pIrp
);

NTSTATUS	_FsFilterDisplayFileName(
	IN	PIRP	_pIrp ,
	IN OPTIONAL PWCHAR	_pFirstDisplayStr ,
	IN OPTIONAL	PSUFFIX	_pSuffix ,
	OUT OPTIONAL PBOOLEAN	_pbIsExe
);

NTSTATUS	_FsFilterCreateCompletion(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp ,
	IN	PVOID	_pContext
);

NTSTATUS	_FsFilterReadDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
);

NTSTATUS	_FsFilterGetFileData(
	IN OPTIONAL	HANDLE	_hFile ,
	IN	PFILE_OBJECT	_pFileObject ,
	IN	PDEVICE_OBJECT	_pFsDeviceObject ,
	IN OUT	PULONG		_pFileData
);

NTSTATUS	_IrpQueryFileInformation(
	IN	PFILE_OBJECT	_pFileObject ,
	IN	PDEVICE_OBJECT	_pFsDeviceObject ,
	IN	FILE_INFORMATION_CLASS _InforClass ,
	OUT	PVOID	_pBuffer ,
	IN	ULONG	_BufferLength
);

NTSTATUS	_IrpCompletion(
	PDEVICE_OBJECT	_pDeviceObject ,
	PIRP	_pIrp ,
	PVOID	_pContext
);

NTSTATUS	_IrpReadFile(
	IN	PFILE_OBJECT	_pFileObject ,
	IN	PDEVICE_OBJECT	_pFsDeviceObject ,
	IN	PLARGE_INTEGER	_pliOffset ,
	IN	ULONG	_Length ,
	OUT	PVOID	_pBuffer
);

NTSTATUS	_CheckVirusFile(
	IN OPTIONAL	HANDLE	_hFile ,
	IN	PFILE_OBJECT	_pFileObject ,
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	OUT	PBOOLEAN	_pbIsVirus
);

NTSTATUS	_FsFilterSetInformationDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
);


NTSTATUS	_CheckVirusThread(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PKTHREAD	_pKThread ,
	IN	PKPROCESS	_pKProcess ,
	OUT	PBOOLEAN	_pbIsVirus ,
	OUT OPTIONAL	PVOID*	_pThreadStartAddress ,
	OUT OPTIONAL	PSIZE_T	_pThreadModulePageSize
);

NTSTATUS	_KillProcess(
	IN	PKPROCESS	_pProcess
);

NTSTATUS	_KillThread(
	IN OPTIONAL	PKPROCESS	_pKProcess ,
	IN PVOID	_pThreadStartAddress ,
	IN	SIZE_T	_ThreadModulePageSize
);

NTSTATUS	_FsFilterWriteDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
);

NTSTATUS	_GetThreadModulePath(
	IN	PKTHREAD	_pKThread ,
	IN	PKPROCESS	_pKProcess ,
	OUT	PUNICODE_STRING	_pRetModulePath ,
	OUT OPTIONAL	PULONG	_pRetNeedLength ,
	OUT OPTIONAL	PVOID*	_pThreadStartAddress ,
	OUT OPTIONAL	PSIZE_T	_pThreadModulePageSize
);

NTSTATUS	_IrpSetFileInformation(
	IN PDEVICE_OBJECT	_pFsDeviceObject ,
	IN	PFILE_OBJECT	_pFileObject ,
	IN	FILE_INFORMATION_CLASS	_InforClass ,
	IN	PVOID	_pBuffer ,
	IN	ULONG	_BufferLen
);

NTSTATUS	_FsFilterDeviceControlDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
);

NTSTATUS	_InitVirusList();

NTSTATUS	_DeleteVirusList();

#endif // !FSPROTECT_H
