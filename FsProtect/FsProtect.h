#ifndef FSPROTECT_H
#define	FSPROTECT_H

#include	<ntifs.h>
#include	<ntdef.h>
#include	<ntddk.h>
#include	<ntdddisk.h>
#include	<wdmsec.h>
#include	<wchar.h>
//#include	<intrin.h>


#define	POOL_TAG	'hqsb'

#define DELAY_ONE_MICROSECOND   (-10)
#define DELAY_ONE_MILLISECOND   (DELAY_ONE_MICROSECOND*1000)
#define DELAY_ONE_SECOND        (DELAY_ONE_MILLISECOND*1000)

#define FlagOn(_F,_SF)        ((_F) & (_SF))

#define SetFlag(_F,_SF)       ((_F) |= (_SF))

#define ClearFlag(_F,_SF)     ((_F) &= ~(_SF))


/**********应用程序和驱动通信相关的宏定义*************/
//获得应用程序发来的等待事件
#define	IOCTL_UserEvent \
CTL_CODE(FILE_DEVICE_UNKNOWN,0x201,METHOD_NEITHER,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//分配共享缓冲区给应用程序来通信
#define	IOCTL_GetShareMemory \
CTL_CODE(FILE_DEVICE_UNKNOWN,0x202,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//通知驱动标记病毒
#define	IOCTL_VirusSet	\
CTL_CODE(FILE_DEVICE_UNKNOWN,0x203,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//通知驱动取消标记病毒
#define	IOCTL_VirusUnset	\
CTL_CODE(FILE_DEVICE_UNKNOWN,0x205,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//将病毒链表中已录入的病毒信息拷贝到日志缓冲区输出
#define	IOCTL_VirusShow	\
CTL_CODE(FILE_DEVICE_UNKNOWN,0x204,METHOD_NEITHER,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//通知驱动是否过滤读请求
#define	IOCTL_ReadControl	\
CTL_CODE(FILE_DEVICE_UNKNOWN,0x206,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//通知驱动是否过滤写请求	
#define	IOCTL_WriteControl	\
CTL_CODE(FILE_DEVICE_UNKNOWN,0x207,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

//通知驱动是否过滤设置文件的请求
#define	IOCTL_SetFileControl	\
CTL_CODE(FILE_DEVICE_UNKNOWN,0x208,METHOD_BUFFERED,FILE_READ_ACCESS | FILE_WRITE_ACCESS)

// 显示驱动全局过滤器
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
// 用来判断一个设备对象是否是本过滤驱动创建的过滤设备
// 自己创建的过滤设备的设备扩展中都有Tag标记
//
#define IS_MY_DEVICE_OBJECT(_devObj) \
    (((_devObj) != NULL) && \
     ((_devObj)->DriverObject == g_pFsFilterDriverObject) && \
      ((_devObj)->DeviceExtension != NULL) && \
	  ((*(ULONG *)(_devObj)->DeviceExtension) == POOL_TAG))

//
// 用来判断一个设备是否是本过滤驱动的控制设备
// 控制设备没有设备扩展
//
#define IS_MY_CONTROL_DEVICE_OBJECT(_devObj) \
    (((_devObj) == g_pFsFilterControlDeviceObject) ? \
             TRUE : FALSE)

//
//	宏：判断设备类型是否是关心的文件系统之一
//	关心的文件系统包括：磁盘文件系统、光盘和网络文件系统
//
#define	IS_DESIRED_DEVICE_TYPE(_type)\
		(((_type) == FILE_DEVICE_DISK_FILE_SYSTEM) || \
		((_type) == FILE_DEVICE_CD_ROM_FILE_SYSTEM) || \
		((_type) == FILE_DEVICE_NETWORK_FILE_SYSTEM))

//
//  宏：通过设备类型获得设备类型的asci字符串
//

#define GET_DEVICE_TYPE_NAME( _type ) \
            ((((_type) > 0) && ((_type) < (sizeof(DeviceTypeNames) / sizeof(PCHAR)))) ? \
                DeviceTypeNames[ (_type) ] : \
                "[Unknown]")
//
// 已知设备类型名称
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


//驱动全局过滤控制器结构体
typedef	struct _FILTER_CONTROL
{
	BOOLEAN	ReadControl;
	BOOLEAN	WriteControl;
	BOOLEAN	SetFileControl;
}FILTER_CONTROL , *PFILTER_CONTROL;


//文件过滤驱动设备扩展
typedef	struct _FSFILTER_DEIVCE_EXTENSION
{
	//标识符用来标识自己创建的设备对象
	ULONG	DeviceTag;

	//绑定的文件系统设备
	PDEVICE_OBJECT	pLowerFsDeviceObject;

	//文件系统相关的块设备，即卷管理器的卷设备
	PDEVICE_OBJECT	pStorageStackDeviceObject;

	//如果绑定了一个卷，那么这是磁盘卷名，否则这是绑定的控制设备名
	UNICODE_STRING	DeviceName;
	//DeviceName的缓冲区
	WCHAR	DeviceNameBuffer[64];
}FSFILTER_DEVICE_EXTENSION , *PFSFILTER_DEVICE_EXTENSION;


//日志缓冲区,用来返回单条日志信息
typedef	struct _ClientLog
{
	ULONG	CharCounts;
	WCHAR	LogBuffer[];
}CLIENT_LOG , *PCLIENT_LOG;

//控制设备的设备扩展
typedef	struct _CONTROL_DEVICE_EXTENSION
{
	//用户等待事件对象
	PKEVENT	pUserEvent;
	//用户共享日志缓存
	PCLIENT_LOG	pClientLog;
	//描述共享日志缓存的MDL
	PMDL	pMdlLog;
	//映射的共享地址
	PVOID	pSharedAddress;
}CONTROL_DEVICE_EXTENSION,*PCONTROL_DEVICE_EXTENSION;


//该结构体用来描述病毒的信息
typedef	struct _Virus
{
	WCHAR	Name[32];	//病毒名
	WCHAR	ProcessName[32];	//病毒可能使用的进程名(暂未使用)
	WCHAR	FileName[32];	//病毒可能使用的文件名(暂未使用)
	ULONG	FileData[4];	//病毒的特征码
}VIRUS_INFOR , *PVIRUS_INFOR;

//该结构体存放病毒的信息,并使用双链表结构
typedef	struct _VirusList
{
	LIST_ENTRY	ListEntry;	//双链表结构指针
	ULONG	Number;	//当前链表在双链表结构中的编号
	VIRUS_INFOR	VirusInfor;	//描述病毒信息的结构体
}VIRUS_LIST,*PVIRUS_LIST;

//病毒一级索引表
PULONG	VirusIndexTable1[0xffffffff]; 

//该结构体用来存放最近一次分析的文件对象的信息
typedef struct _FileObjectContext
{
	PFILE_OBJECT	pFileObject;
	PVOID	pFsContext;
	BOOLEAN		bIsVirus;
	ULONG	FileData[4];
}FILEOBJCONTEXT , *PFILEOBJCONTEXT;


//该结构体用来存放文件后缀名的信息,在输出文件名的时候用到
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


//声明未导出的函数
typedef NTSTATUS( *_ZwQueryInformationThread ) (
	__in HANDLE ThreadHandle ,
	__in PROCESSINFOCLASS ThreadInformationClass ,
	__out PVOID ThreadInformation ,
	__in ULONG ThreadInformationLength ,
	__out_opt PULONG ReturnLength
	);
_ZwQueryInformationThread ZwQueryInformationThread = NULL;

typedef	NTSTATUS  (*_ZwQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle ,
	_In_      PROCESSINFOCLASS ProcessInformationClass ,
	_Out_     PVOID            ProcessInformation ,
	_In_      ULONG            ProcessInformationLength ,
	_Out_opt_ PULONG           ReturnLength
);
_ZwQueryInformationProcess	ZwQueryInformationProcess = NULL;

//声明机器码
typedef	UINT64( __fastcall *ASM )();

CHAR ShellCode[] = "\x0F\x20\xC0\x81\xE0\xFF\xFF\xFE\xFF\x0F\x22\xC0\xC3";

//函数声明

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

NTSTATUS	_FsProtectDefaultDispatch(
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


NTSTATUS	_CheckProcessOrThread(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	OPTIONAL	PKTHREAD	_pKThread ,
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

NTSTATUS	_GetThreadModuleInfor(
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

NTSTATUS	_GetProcessName(
	IN	PKPROCESS	_pKprocess ,
	IN OUT	PUNICODE_STRING	_pProcessName ,
	OUT	OPTIONAL PULONG	_pRetLength
);

VOID	_GetProcessNameOffset();

NTSTATUS	_CheckProcess(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PKPROCESS		_pKprocess ,
	OUT	PBOOLEAN		_pbIsVirus
);

NTSTATUS	_GetProcessImageName(
	IN	PKPROCESS	_pKprocess ,
	OUT	PUNICODE_STRING	_pProcessImageName ,
	OUT	OPTIONAL PULONG	_pNeedLength
);

NTSTATUS	_DeleteVirusFile(
	IN	PFILE_OBJECT	_pFileObject
);

#endif // !FSPROTECT_H
