/*
	小型反病毒驱动,sfilter型过滤框架
						---PowerfulGun
*/

#include	"FsProtect.h"

//全局变量
PDEVICE_OBJECT	g_pFsFilterControlDeviceObject = NULL;	//本过滤驱动使用的控制设备
PDRIVER_OBJECT	g_pFsFilterDriverObject = NULL;	//本过滤驱动对象
FAST_MUTEX	g_FastMutexAttach;
FILEOBJCONTEXT	g_LastFileContext;	//用来保存之前的文件对象信息
PVOID	g_pSkipFileObjectContext;	//用来保存需要跳过检查的文件对象
LIST_ENTRY	g_VirusListHead;	//病毒链表头
HANDLE	g_hRegistrySub = NULL;	//注册表句柄
FILTER_CONTROL	g_Control = { TRUE ,TRUE,TRUE};	//全局驱动过滤控制器

//本地病毒库
VIRUS	LocalVirus[] =
{
	//L"mspaint",
	//L"mspaint.exe",
	//L"mspaint.exe",
	//0x0,0xffc85d29 ,0xa5acf974 ,0x808080,	//mspaint的特征码

	//L"notepad",
	//L"notepad.exe",
	//L"notepad.exe",
	//0x103,0x577e,0x553b12,0xf43ddac7,	//notepad的特征码

	L"机房481",								//机房481病毒,该病毒会将U盘文件夹隐藏,并生成同名exe程序冒充文件夹(图标是xp系统文件夹的图标)
	L"explorer.exe",						//该病毒使用自己的进程explorer.exe,冒充windows的同名资源管理器进程(Windows自己的explorer.exe较大)
	L"explorer.exe",						//该病毒在C:\Program Files (x86)\explorer.exe保留自己,而Windows的是在C:\Windows\explorer.exe
	0x0,0xcc58c22f,0x861ad7ed,0xe418e767,	//其特征码

	L"机房665",								//机房665病毒,该病毒会将U盘文件夹隐藏,并生成同名exe程序冒充文件夹(图标是Win7系统文件夹的图标)
	L"rundll32.exe",						//该病毒使用自己的进程rundll32.exe,冒充windows的同名rundll32.exe
	L"rundll32.exe",						//该病毒在C:\Users\Administrator\AppData\Roaming\Microsoft\Office\rundll32.exe保留,而Windows的是在C:\Windows\System32\rundll32.exe
	0x3300444f,0xddd8dd32,0x8c24,0x3030000,	//其特征码

	0,0,0,0,0,0,0	//代表末尾,遍历到这里就退出
};

/*
驱动入口
第一步是生成自己使用的控制设备CDO，用来和应用程序通信
*/
NTSTATUS	DriverEntry(
	IN	PDRIVER_OBJECT	_pDriverObject ,
	IN	PUNICODE_STRING	_pRegistryPath
)
{
	NTSTATUS	status = STATUS_SUCCESS;
	ULONG	i;
	PFAST_IO_DISPATCH	pFastIoDispatch = NULL;
	UNICODE_STRING	DeviceName , Win32Name;
	OBJECT_ATTRIBUTES	ObjAttr;
	ULONG	Result;
	HANDLE	hRegistryRoot;
	UNICODE_STRING	RegistrySub;


	//初始化快速互斥体，之后绑定设备时用到
	ExInitializeFastMutex( &g_FastMutexAttach );

	//保存自己的驱动对象之后会用到
	g_pFsFilterDriverObject = _pDriverObject;

	//打印驱动注册表路径
	KdPrint( ("RegistryPath:%wZ\n" , _pRegistryPath) );
	//打开注册表项
	InitializeObjectAttributes(
		&ObjAttr ,
		_pRegistryPath ,
		OBJ_CASE_INSENSITIVE,
		NULL , NULL );
	status = ZwCreateKey(
		&hRegistryRoot ,
		KEY_ALL_ACCESS ,
		&ObjAttr ,
		0 , NULL ,
		REG_OPTION_NON_VOLATILE ,
		&Result );
	if (!NT_SUCCESS( status ))
	{
		KdPrint( ("Get RegistryRoot fail,status=%x\n" , status) );
	}

	RtlInitUnicodeString(
		&RegistrySub ,
		L"Virus" );
	InitializeObjectAttributes(
		&ObjAttr ,
		&RegistrySub ,
		OBJ_CASE_INSENSITIVE ,
		hRegistryRoot , NULL );
	status = ZwCreateKey(
		&g_hRegistrySub ,
		KEY_ALL_ACCESS ,
		&ObjAttr ,
		0 , NULL ,
		REG_OPTION_NON_VOLATILE ,
		&Result );
	if (!NT_SUCCESS( status ))
	{
		KdPrint( ("Get RegistrySub fail,status=%x\n" , status) );
	}
	//关闭根注册表句柄
	ZwClose( hRegistryRoot );

	//初始化病毒链表,病毒链表用来在之后识别病毒
	status = _InitVirusList();
	if (!NT_SUCCESS( status ))//如果不成功就没有必要执行之后的文件系统绑定操作了
		return	status;

	do
	{
		//定义自己的控制设备名
		RtlInitUnicodeString( &DeviceName , L"\\FileSystem\\Filters\\FsProtect" );
		//生成本驱动的控制设备
		status = IoCreateDevice(
			_pDriverObject ,
			sizeof(CONTROL_DEVICE_EXTENSION) ,	//设备扩展
			&DeviceName ,
			FILE_DEVICE_DISK_FILE_SYSTEM ,
			FILE_DEVICE_SECURE_OPEN ,
			FALSE ,
			&g_pFsFilterControlDeviceObject );
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("FsFilter.DriverEntry: error create CDO:%wZ, status = %x\n" , &DeviceName , status) );

			break;
		}
		//初始化设备扩展
		RtlZeroMemory(
			g_pFsFilterControlDeviceObject->DeviceExtension ,
			sizeof( CONTROL_DEVICE_EXTENSION ) );

		g_pFsFilterControlDeviceObject->Flags |= DO_BUFFERED_IO;

		//创建符号链接名
		RtlInitUnicodeString(
			&Win32Name ,
			L"\\DosDevices\\PowerfulGun_FsProtect" );
		status =
			IoCreateSymbolicLink(
			&Win32Name ,
			&DeviceName );
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("FsFilter.DriverEntry:error create SymbolicLink\n\
				status=%x\n" , status) );
			break;
		}

		//设置默认分发函数
		for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		{
			_pDriverObject->MajorFunction[i] = _FsFilterDefaultDispatch;
		}

		//设置特殊的分发函数
		_pDriverObject->MajorFunction[IRP_MJ_CREATE] = _FsFilterCreateDispatch;
		//_pDriverObject->MajorFunction[IRP_MJ_CREATE_NAMED_PIPE] = _FsFilterCreateDispatch;
		//_pDriverObject->MajorFunction[IRP_MJ_CREATE_MAILSLOT] = _FsFilterCreateDispatch;

		_pDriverObject->MajorFunction[IRP_MJ_READ] = _FsFilterReadDispatch;	//拦截读请求

		_pDriverObject->MajorFunction[IRP_MJ_WRITE] = _FsFilterWriteDispatch;	//拦截写请求

		_pDriverObject->MajorFunction[IRP_MJ_CLOSE] = _FsFilterCloseDispatch;

		_pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = _FsFilterDeviceControlDispatch;

		_pDriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = _FsFilterControlDispatch;

		_pDriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = _FsFilterSetInformationDispatch;	//拦截设置文件属性请求

		_pDriverObject->DriverUnload = _DriverUnload;

		//设置该驱动的快速io分发表
		pFastIoDispatch = ExAllocatePoolWithTag(
			NonPagedPool , sizeof( FAST_IO_DISPATCH ) , POOL_TAG );
		if (!pFastIoDispatch)
		{
			KdPrint( ("ExAllocatePoolWithTag fail") );
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		RtlZeroMemory( pFastIoDispatch , sizeof( FAST_IO_DISPATCH ) );
		pFastIoDispatch->SizeOfFastIoDispatch = sizeof( FAST_IO_DISPATCH );

		//设置以下所有快速函数
		pFastIoDispatch->FastIoCheckIfPossible = _FastIoCheckIfPossible;
		pFastIoDispatch->FastIoRead = _FastIoRead;
		pFastIoDispatch->FastIoWrite = _FastIoWrite;
		pFastIoDispatch->FastIoQueryBasicInfo = _FastIoQueryBasicInfo;
		pFastIoDispatch->FastIoQueryStandardInfo = _FastIoQueryStandardInfo;
		pFastIoDispatch->FastIoLock = _FastIoLock;
		pFastIoDispatch->FastIoUnlockSingle = _FastIoUnlockSingle;
		pFastIoDispatch->FastIoUnlockAll = _FastIoUnlockAll;
		pFastIoDispatch->FastIoUnlockAllByKey = _FastIoUnlockAllByKey;
		pFastIoDispatch->FastIoDeviceControl = _FastIoDeviceControl;
		pFastIoDispatch->FastIoDetachDevice = _FastIoDetachDevice;
		pFastIoDispatch->FastIoQueryNetworkOpenInfo = _FastIoQueryNetworkOpenInfo;
		pFastIoDispatch->MdlRead = _FastIoMdlRead;
		pFastIoDispatch->MdlReadComplete = _FastIoMdlReadComplete;
		pFastIoDispatch->PrepareMdlWrite = _FastIoPrepareMdlWrite;
		pFastIoDispatch->MdlWriteComplete = _FastIoMdlWriteComplete;
		pFastIoDispatch->FastIoReadCompressed = _FastIoReadCompressed;
		pFastIoDispatch->FastIoWriteCompressed = _FastIoWriteCompressed;
		pFastIoDispatch->MdlReadCompleteCompressed = _FastIoMdlReadCompleteCompressed;
		pFastIoDispatch->MdlWriteCompleteCompressed = _FastIoMdlWriteCompleteCompressed;
		pFastIoDispatch->FastIoQueryOpen = _FastIoQueryOpen;

		//将快速分发表指定给驱动对象
		_pDriverObject->FastIoDispatch = pFastIoDispatch;

		//注册文件系统激活回调,当有文件系统激活时会调用FsChangeCallBack
		status = IoRegisterFsRegistrationChange( _pDriverObject , _FsChangeCallback );
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("FsFilter.DriverEntry.IoRegisterFsRegistrationChange fail\n status=%x\n" , status) );
			break;
		}

	} while (FALSE);

	//错误处理
	//判断status是否成功，失败要释放资源
	if (!NT_SUCCESS( status ))
	{
		if (g_pFsFilterControlDeviceObject)
			IoDeleteDevice( g_pFsFilterControlDeviceObject );

		if (pFastIoDispatch)
		{
			_pDriverObject->FastIoDispatch = NULL;
			ExFreePoolWithTag( pFastIoDispatch , POOL_TAG );

			//删除符号链接名
			IoDeleteSymbolicLink( &Win32Name );
		}

		return	status;
	}

	return	STATUS_SUCCESS;
}

/*
_FsFilterDefaultDispatch负责不需要处理，直接下发到下层驱动的irp
*/
NTSTATUS	_FsFilterDefaultDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
)
{
	//判断是否是自己的控制设备
	if (IS_MY_CONTROL_DEVICE_OBJECT( _pDeviceObject ))
	{
		_pIrp->IoStatus.Status = STATUS_SUCCESS;
		_pIrp->IoStatus.Information = 0;
		IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
		return	STATUS_SUCCESS;
	}

	//请求直接下发到过滤设备的下层设备
	IoSkipCurrentIrpStackLocation( _pIrp );
	return	IoCallDriver(
		((PFSFILTER_DEVICE_EXTENSION)_pDeviceObject->DeviceExtension)->pLowerFsDeviceObject ,
		_pIrp );
}

/*
_FsFilterAttachDeviceToDeviceStack
负责将过滤设备绑定到文件系统设备栈中
参数:
sourceDevice:过滤设备
targetDevice:目标设备
*LowerDeviceObject:用来返回下层设备
*/
NTSTATUS	_FsFilterAttachToDeviceStack(
	IN	PDEVICE_OBJECT	_pSourceDevice ,
	IN	PDEVICE_OBJECT	_pTargetDevice ,
	IN OUT	PDEVICE_OBJECT*	_pLowerDevice
)
{
	//测试该函数是否可以使用分页内存
	PAGED_CODE();

	return	IoAttachDeviceToDeviceStackSafe(
		_pSourceDevice ,
		_pTargetDevice ,
		_pLowerDevice );

	/*
	//低版本调用
	*_pLowerDevice  = _pTargetDeivce;
	*_pLowerDevice = IoAttachDeviceToDeviceStack(_pSourceDevice,_pTargetDevice);
	if(*_pLowerDevice == NULL)
	return	STATUS_NO_SUCH_DEVICE;

	return	STATUS_SUCCESS;
	*/
}

/*
_FsChangeCallback
在有文件系统激活时会调用此函数
参数:
pFsControlDeviceObject是文件系统控制设备栈的栈顶设备
FsActive表示文件系统的激活或者卸载
*/
VOID	_FsChangeCallback(
	IN	PDEVICE_OBJECT	_pFsControlDeviceObject ,
	IN	BOOLEAN		_bFsActive
)
{
	UNICODE_STRING	DeviceName;
	WCHAR	DeviceNameBuffer[64];
	PAGED_CODE();

	//将设备名打印出来
	RtlInitEmptyUnicodeString( &DeviceName , DeviceNameBuffer , sizeof( DeviceNameBuffer ) );
	_FsFilterGetObjectName( _pFsControlDeviceObject , &DeviceName );
	KdPrint( ("[_FsChangeCallback]\n\
		%s\n\
		DeviceObject=%p\n\
		Name:%wZ\n\
		DeviceType=%s" , \
		(_bFsActive) ? "FileSystem Active" : "FIleSystem Deactive" , \
		_pFsControlDeviceObject , &DeviceName ,
		GET_DEVICE_TYPE_NAME( _pFsControlDeviceObject->DeviceType )) );

	/*
	如果是文件系统激活，那么就要绑定文件系统的控制设备
	如果是文件系统卸载，就要解除原有的绑定
	*/
	if (_bFsActive)
	{
		_FsFilterAttachToFsControlDevice( _pFsControlDeviceObject , &DeviceName );
	}
	else
	{
		_FsFilterDetachFsControlDevice( _pFsControlDeviceObject );
	}
}

/*
该函数获得对象名称
参数:
pObject对象指针
pUNICODE_STRING类型指针
*/
VOID	_FsFilterGetObjectName(
	IN	PVOID	_pObject ,
	IN OUT	PUNICODE_STRING	_pName
)
{
	NTSTATUS	status;
	POBJECT_NAME_INFORMATION	pNameInfo;
	CHAR	NameInfoBuffer[512];
	ULONG	RetLength;


	pNameInfo = (POBJECT_NAME_INFORMATION)NameInfoBuffer;

	status = ObQueryNameString(
		_pObject ,
		pNameInfo ,
		sizeof( NameInfoBuffer ) ,
		&RetLength );

	_pName->Length = 0;
	if (NT_SUCCESS( status ))
	{
		RtlCopyUnicodeString( _pName , &pNameInfo->Name );
	}

}

/*
下面的函数用来绑定文件系统的控制设备
绑定之后当有卷挂载时便可知道
参数：
FsControlDevice文件系统的控制设备
DeviceName设备名称
*/
NTSTATUS	_FsFilterAttachToFsControlDevice(
	IN	PDEVICE_OBJECT	_pFsControlDevice ,
	IN	PUNICODE_STRING	_pDeviceName
)
{
	NTSTATUS	status;
	UNICODE_STRING	DriverName , FsRecName;
	WCHAR	DriverNameBuffer[64];
	PDEVICE_OBJECT	pFilterDeviceObject;
	PFSFILTER_DEVICE_EXTENSION	pDevExt;

	PAGED_CODE();

	do
	{
		//检查设备类型是否是关心的设备
		if (!IS_DESIRED_DEVICE_TYPE( _pFsControlDevice->DeviceType ))
			return	STATUS_SUCCESS;

		//准备获得该设备所属的驱动名称
		RtlInitEmptyUnicodeString(
			&DriverName ,
			DriverNameBuffer ,
			sizeof( DriverNameBuffer ) );
		_FsFilterGetObjectName( _pFsControlDevice->DriverObject , &DriverName );

		RtlInitUnicodeString( &FsRecName , L"\\FileSystem\\Fs_Rec" );
		//查看驱动是否是文件系统识别器，是就直接返回跳过绑定
		if (RtlCompareUnicodeString( &DriverName , &FsRecName , TRUE ) == 0)
			return	STATUS_SUCCESS;

		//生成一个新的设备用作过滤设备
		status = IoCreateDevice(
			g_pFsFilterDriverObject ,
			sizeof( FSFILTER_DEVICE_EXTENSION ) ,
			NULL ,
			_pFsControlDevice->DeviceType ,
			0 ,
			FALSE ,
			&pFilterDeviceObject );
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("_FsFilterAttachToControlDevice.IoCreateDevice fail ,status=%x\n" , status) );
			break;
		}

		//生成过滤设备后要从原先设备拷贝各种标识，为了让系统看起来过滤设备和原来设备没什么区别
		if (FlagOn( _pFsControlDevice->Flags , DO_BUFFERED_IO ))
			SetFlag( pFilterDeviceObject->Flags , DO_BUFFERED_IO );

		if (FlagOn( _pFsControlDevice->Flags , DO_DIRECT_IO ))
			SetFlag( pFilterDeviceObject->Flags , DO_DIRECT_IO );

		if (FlagOn( _pFsControlDevice->Characteristics , FILE_DEVICE_SECURE_OPEN ))
			SetFlag( pFilterDeviceObject->Characteristics , FILE_DEVICE_SECURE_OPEN );

		//获得过滤设备的设备扩展指针
		pDevExt = pFilterDeviceObject->DeviceExtension;
		//使用绑定函数将生成的过滤设备绑定到文件系统控制设备栈
		status = _FsFilterAttachToDeviceStack(
			pFilterDeviceObject ,
			_pFsControlDevice ,
			&pDevExt->pLowerFsDeviceObject );
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("_FsFilterAttachToControlDevice._FsFilterAttachToDeviceStack fail,status=%x\n" , status) );
			break;
		}

		//将文件系统控制设备的设备名称记录进过滤设备的设备扩展中
		RtlInitEmptyUnicodeString(
			&pDevExt->DeviceName ,
			pDevExt->DeviceNameBuffer ,
			sizeof( pDevExt->DeviceNameBuffer ) );
		RtlCopyUnicodeString( &pDevExt->DeviceName , _pDeviceName );
		//设置过滤设备已初始化
		pDevExt->DeviceTag = POOL_TAG;
		ClearFlag( pFilterDeviceObject->Flags , DO_DEVICE_INITIALIZING );

		//如果目标操作系统内核版本大于0x501，就有EnumerateDeviceObjectList等函数
		//就可以枚举所有卷，逐个绑定
		status = _FsFilterEnumrateFileSystemVolumes(
			_pFsControlDevice );
		if (!NT_SUCCESS( status ))
		{
			//解除对文件系统控制设备的绑定
			IoDetachDevice( pDevExt->pLowerFsDeviceObject );
			break;
		}
	} while (FALSE);

	//错误处理
	if (!NT_SUCCESS( status ))
	{
		if (pFilterDeviceObject)
		{
			IoDeleteDevice( pFilterDeviceObject );
		}
	}

	return	status;
}

/*
该函数枚举文件系统上的所有的卷，并绑定
目标文件系统可能早已激活，并且卷都已挂载，所以可以调用此函数
_pFsControlDevice是文件系统的控制设备
*/
NTSTATUS	_FsFilterEnumrateFileSystemVolumes(
	IN	PDEVICE_OBJECT	_pFsControlDevice
)
{
	ULONG	i;
	NTSTATUS	status;
	ULONG	FsDeviceNum;
	PDEVICE_OBJECT*	pDeviceList;
	PDEVICE_OBJECT	pFilterDevice = NULL;
	PFSFILTER_DEVICE_EXTENSION	pDevExt = NULL;
	PDEVICE_OBJECT	pStorageStackDevice = NULL;
	UNICODE_STRING	DeviceName;
	WCHAR	DeviceNameBuffer[64];
	BOOLEAN	IsShadowCopyVolume;
	PAGED_CODE();


	//找出文件系统设备数量有多少，通过传入参数0实现
	status =
		IoEnumerateDeviceObjectList(
		_pFsControlDevice->DriverObject ,
		NULL ,
		0 ,		//传入数量0
		&FsDeviceNum );	//函数会通过FsDeviceNum返回实际数量
	if (!NT_SUCCESS( status ))
	{
		ASSERT( status == STATUS_BUFFER_TOO_SMALL );

		//为设备表分配内存
		FsDeviceNum += 8;	//获得一些额外的槽
		pDeviceList =
			ExAllocatePoolWithTag(
			NonPagedPool ,
			FsDeviceNum * sizeof( PDEVICE_OBJECT ) ,
			POOL_TAG );
		if (pDeviceList == NULL)
			return	STATUS_INSUFFICIENT_RESOURCES;

		//再次获得文件系统设备表
		status =
			IoEnumerateDeviceObjectList(
			_pFsControlDevice->DriverObject ,
			pDeviceList ,
			(FsDeviceNum * sizeof( PDEVICE_OBJECT )) ,
			&FsDeviceNum );
		if (!NT_SUCCESS( status ))
		{
			ExFreePool( pDeviceList );
			return	status;
		}

		//遍历文件系统设备表中的设备，并判断是否应该绑定
		for (i = 0; i < FsDeviceNum; i++)
		{
			pStorageStackDevice = NULL;

			try
			{
				/*
				如果有以下情况就不用绑定：
				这是个控制设备（就是传入的参数）
				这个设备类型不匹配
				这个设备已经被我绑定
				*/
				if ((pDeviceList[i] == _pFsControlDevice) ||
					(pDeviceList[i]->DeviceType != _pFsControlDevice->DeviceType) ||
					_FsIsAttachedToDevice( pDeviceList[i] , NULL ))
				{
					leave;
				}

				/*
				差看此设备是否有名称，有名称就一定是控制设备，就不绑定
				有的文件系统驱动可能有多个控制设备，如fastfat
				*/
				RtlInitEmptyUnicodeString(
					&DeviceName ,
					DeviceNameBuffer ,
					sizeof( DeviceNameBuffer ) );
				_FsFilterGetBaseDeviceObjectName( pDeviceList[i] , &DeviceName );
				if (DeviceName.Length > 0)
					leave;

				//得到块设备对象，块设备对象通过vpb与文件系统卷设备对象
				//关联，只绑定有关联块设备的文件系统设备对象
				//该函数会导致块设备（pStorageStackDevice）的引用增加
				//引用会在finally块中解除
				status =
					IoGetDiskDeviceObject(
					pDeviceList[i] ,
					&pStorageStackDevice );
				if (!NT_SUCCESS( status ))
					leave;

				//通过获得的块设备对象，判断是否是一个卷影设备
				//不绑定卷影设备
				status =
					_FsFilterIsShadowCopyVolume(
					pStorageStackDevice ,
					&IsShadowCopyVolume );
				if (NT_SUCCESS( status ) &&
					IsShadowCopyVolume)
				{
					//打印卷影设备名称
					RtlInitEmptyUnicodeString(
						&DeviceName ,
						DeviceNameBuffer ,
						sizeof( DeviceNameBuffer ) );

					_FsFilterGetObjectName(
						pStorageStackDevice ,
						&DeviceName );

					KdPrint( ("_FsFilterEnumerateFileSystemVolumes:\n\
							%wZ\n\
							this is a shadow copy volume,not attach\n" , &DeviceName) );

					//离开try块，进入finally块解除引用，
					//然后进入下一次循环
					leave;
				}

				//创建一个过滤设备来绑定
				status =
					IoCreateDevice(
					g_pFsFilterDriverObject ,
					sizeof( FSFILTER_DEVICE_EXTENSION ) ,
					NULL ,	//无名
					pDeviceList[i]->DeviceType ,
					0 ,
					FALSE ,
					&pFilterDevice );
				if (!NT_SUCCESS( status ))
					leave;

				//设置过滤设备中设备扩展中的标识、块设备
				pDevExt = pFilterDevice->DeviceExtension;
				pDevExt->DeviceTag = POOL_TAG;
				pDevExt->pStorageStackDeviceObject = pStorageStackDevice;

				RtlInitEmptyUnicodeString(
					&pDevExt->DeviceName ,
					pDevExt->DeviceNameBuffer ,
					sizeof( pDevExt->DeviceNameBuffer ) );
				_FsFilterGetObjectName(
					pStorageStackDevice ,
					&pDevExt->DeviceName );

				/*
				再次验证是否设备已经绑定过
				使用一个快速互斥体，确保查询或绑定的操纵是原子进行
				*/
				ExAcquireFastMutex( &g_FastMutexAttach );

				if (!_FsIsAttachedToDevice( pDeviceList[i] , NULL ))
				{
					//绑定
					status = _FsFilterAttachToMountedDevice(
						pDeviceList[i] ,
						pFilterDevice );
					if (!NT_SUCCESS( status ))
					{
						/*
						如果绑定失败就删除创建的设备
						失败原因之一就是卷设备正在挂载，
						DO_DEVICE_INITIALIZING 标识没有清除
						*/
						IoDeleteDevice( pFilterDevice );
					}

				}
				else // if (!_FsIsAttachedToDevice( &pDeviceList[i] , NULL ))
				{
					//文件系统设备被判断已经被绑定
					//删除创建的过滤设备
					IoDeleteDevice( pFilterDevice );
				} //end if(!_FsIsAttachedToDevice( &pDeviceList[i] , NULL ))

				  //释放快速互斥体
				ExReleaseFastMutex( &g_FastMutexAttach );
			}
			finally
			{
				/*
				解除由IoGetDiskDeviceObject增加的对块设备的引用
				*/
				if (pStorageStackDevice != NULL)
				{
					ObDereferenceObject( pStorageStackDevice );
				}

				/*
				解除由IoEnumerateDeviceObjectList增加的
				对文件系统设备栈中的设备的引用
				*/
				ObDereferenceObject( pDeviceList[i] );
			}

		}	//end for (i = 0; i < FsDeviceNum; i++)

			//忽略绑定错误只返回STATUS_SUCCESS
		status = STATUS_SUCCESS;

		//删除设备表占用的内存
		ExFreePool( pDeviceList );

	}//end if(!NT_SUCCESS(STATUS))

	 //如果调用IoEnumerateDeviceObjectList失败
	 //直接返回失败的status
	 //否则返回的都是上面设置的STATUS_SUCCESS
	return	status;
}


/*
当枚举文件系统设备表时调用此函数获得设备栈底层设备的设备名
如果底层设备无名就返回空字符串
参数:
pDeviceObject 文件系统设备
pDeviceName 用来返回设备名称
*/
VOID	_FsFilterGetBaseDeviceObjectName(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN OUT	PUNICODE_STRING	_pDeviceName
)
{
	PDEVICE_OBJECT	pFsBaseDevice = NULL;

	//获得底层设备
	pFsBaseDevice =
		IoGetDeviceAttachmentBaseRef( _pDeviceObject );

	//获得底层设备名
	_FsFilterGetObjectName( pFsBaseDevice , _pDeviceName );

	//要解除底层设备的引用,因为IoGetDeviceAttachmentBaseRef会增加对底层设备的引用
	ObDereferenceObject( pFsBaseDevice );
}


/*该函数遍历设备栈，查看是否有自己生成的设备，如果有就通过
AttachedDeviceObject返回该设备
如果我们绑定了设备栈返回TRUE，否则FALSE
*/
BOOLEAN	_FsIsAttachedToDevice(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	OUT OPTIONAL	PDEVICE_OBJECT* _ppAttachedDeviceObject
)
{
	PAGED_CODE();
	PDEVICE_OBJECT	pCurrentDevObj , pNextDevObj;


	/*
	先获得该设备栈顶端设备
	该调用会增加顶端设备对象的引用计数
	*/
	pCurrentDevObj =
		IoGetAttachedDeviceReference( _pDeviceObject );

	//自上而下扫描设备栈，找出自己的设备
	do
	{
		if (IS_MY_DEVICE_OBJECT( pCurrentDevObj ))
		{
			//找到了自己的设备，如果要返回这个设备对象
			//这个设备对象需要在函数外解除引用
			//不返回就立即解除引用
			if (ARGUMENT_PRESENT( _ppAttachedDeviceObject ))
			{
				*_ppAttachedDeviceObject = pCurrentDevObj;
			}
			else
			{
				ObDereferenceObject( pCurrentDevObj );
			}

			return	TRUE;
		}

		//获得设备栈中下一个设备，该调用会增加下层设备的引用计数
		pNextDevObj =
			IoGetLowerDeviceObject( pCurrentDevObj );

		//解除设备栈中上一个设备的引用
		ObDereferenceObject( pCurrentDevObj );

		pCurrentDevObj = pNextDevObj;
	} while (pCurrentDevObj != NULL);

	//如果没找到就返回FALSE
	if (ARGUMENT_PRESENT( _ppAttachedDeviceObject ))
		*_ppAttachedDeviceObject = NULL;

	return	FALSE;
}


/*
此函数会绑定一个已挂载的文件系统卷设备
DeviceObject就是被绑的设备(文件系统的卷设备)
FilterDeviceObject是自己的过滤设备
*/
NTSTATUS	_FsFilterAttachToMountedDevice(
	IN	PDEVICE_OBJECT	_pFsDeviceObject ,
	IN	PDEVICE_OBJECT	_pFilterDeviceObject
)
{
	NTSTATUS	status;
	ULONG	i;
	LARGE_INTEGER	liInterval;
	PFSFILTER_DEVICE_EXTENSION	pDevExt =
		_pFilterDeviceObject->DeviceExtension;

	PAGED_CODE();

	ASSERT( IS_MY_DEVICE_OBJECT( _pFilterDeviceObject ) );

	liInterval.QuadPart = (500 * DELAY_ONE_MILLISECOND);

	//在绑定设备之前还需要再设置一些过滤设备的标识
	if (FlagOn( _pFsDeviceObject->Flags , DO_BUFFERED_IO ))
	{
		SetFlag( _pFilterDeviceObject->Flags , DO_BUFFERED_IO );
	}
	if (FlagOn( _pFsDeviceObject->Flags , DO_DIRECT_IO ))
	{
		SetFlag( _pFilterDeviceObject->Flags , DO_DIRECT_IO );
	}

	/*
	循环尝试绑定设备对象
	如果磁盘有特殊的操作比如mount或dismount
	绑定有可能失败，所以反复尝试避开巧合
	*/
	for (i = 0; i < 8; i++)
	{
		status =
			_FsFilterAttachToDeviceStack(
			_pFilterDeviceObject ,
			_pFsDeviceObject ,
			&pDevExt->pLowerFsDeviceObject );
		if (NT_SUCCESS( status ))
		{
			ClearFlag( _pFilterDeviceObject->Flags , DO_DEVICE_INITIALIZING );
			return	STATUS_SUCCESS;
		}

		//如果碰巧绑定失败
		//就把当前线程延迟500ms后再继续绑定
		KeDelayExecutionThread(
			KernelMode ,
			FALSE ,
			&liInterval );
	}

	return	status;
}


/*
该函数判断给定的块设备是否是一个卷影拷贝设备
卷影拷贝设备从Windows xp之后出现，卷影拷贝设备所属驱动的驱动名
为\Driver\VolSnap，并且设备标记为read-only
Windows Server 2003上通过查看设备的DeviceType是FILE_DEVICE_VIRTUAL_DISK
来判断是卷影拷贝设备
参数：
StorageStackDeviceObject是块设备对象
IsShadowCopy返回是否是卷影设备
*/
NTSTATUS	_FsFilterIsShadowCopyVolume(
	IN	PDEVICE_OBJECT	_pStorageStackDeviceObject ,
	OUT	PBOOLEAN	_pbIsShadowCopy
)
{
	PAGED_CODE();
	UNICODE_STRING	VolSnapDriverName;
	POBJECT_NAME_INFORMATION	pStorageDriverName;
	WCHAR	Buffer[128];
	NTSTATUS	status;
	ULONG	RetLength;

	//默认认为不是
	*_pbIsShadowCopy = FALSE;

	//获得块设备名称
	pStorageDriverName = (POBJECT_NAME_INFORMATION)Buffer;
	status =
		ObQueryNameString(
		_pStorageStackDeviceObject ,
		pStorageDriverName ,
		sizeof( Buffer ) ,
		&RetLength );
	if (!NT_SUCCESS( status ))
		return	status;

	RtlInitUnicodeString(
		&VolSnapDriverName ,
		L"\\Driver\\VolSnap" );
	//判断名称是否是“\Driver\VolSnap”
	if (RtlEqualUnicodeString(
		&pStorageDriverName->Name ,
		&VolSnapDriverName ,
		TRUE ))
	{
		*_pbIsShadowCopy = TRUE;
		return	STATUS_SUCCESS;
	}

	/*
	Windows Server 2003 之后的版本
	通过查看设备类型是否是FILE_DEVICE_VIRTUAL_DISK
	并且卷影设备是个read-only设备
	*/
	PIRP	pIrp;
	KEVENT	WaitEvent;
	IO_STATUS_BLOCK	iosb;
	//如果这个设备类型不是FILE_DEVICE_VIRTUAL_DISK那就不是
	if (_pStorageStackDeviceObject->DeviceType !=
		FILE_DEVICE_VIRTUAL_DISK)
		return	STATUS_SUCCESS;

	//如果是FILE_DEVICE_VIRTUAL_DISK
	//再构造一个查询设备是否可写的IRP，并发送
	//You need to be careful which device types you do this operation
	//on.  It is accurate for this type but for other device
	//types it may return misleading information.  For example the
	//current microsoft cdrom driver always returns CD media as
	//readonly, even if the media may be writable.  On other types
	//this state may change.

	KeInitializeEvent(
		&WaitEvent ,
		NotificationEvent ,
		FALSE );
	//创建同步Irp
	pIrp = IoBuildDeviceIoControlRequest(
		IOCTL_DISK_IS_WRITABLE ,
		_pStorageStackDeviceObject ,
		NULL ,
		0 ,
		NULL ,
		0 ,
		FALSE ,	//EXternal
		&WaitEvent ,
		&iosb );
	if (pIrp == NULL)
		return	STATUS_INSUFFICIENT_RESOURCES;

	//将Irp发送给设备
	status = IoCallDriver( _pStorageStackDeviceObject , pIrp );
	if (status == STATUS_PENDING)
	{
		KeWaitForSingleObject(
			&WaitEvent ,
			Executive ,
			KernelMode ,
			FALSE ,
			NULL );

		status = iosb.Status;
	}

	//如果设备有写保护，就是一个卷影拷贝设备
	if (status == STATUS_MEDIA_WRITE_PROTECTED)
	{
		*_pbIsShadowCopy = TRUE;
		status = STATUS_SUCCESS;
	}

	return	status;
}


/*
该函数处理IRP_MJ_FILE_SYSTEM_CONTROL
有以下几个不同的次功能号要处理：
1.IRP_MN_MOUNT_VOLUME，这是一个卷被挂载，是绑定文件系统卷设备的时机
2.IRP_MN_LOAD_FILE_SYSTEM，如果之前绑定的控制设备是文件系统识别器，
这是文件系统识别器收到的要加载真正的文件系统的请求
3.IRP_MN_USER_FS_REQUEST，此时可以从
Irpsp->Parameters.FileSystemControl.FsControlCode得到一个控制码，
当控制码为FSCTL_DISMOUNT_VOLUME时，说明这是一个磁盘在解挂载，
但u盘的手工拔出并不会导致发送这个请求，暂不管
参数:
自己的过滤设备(绑定在文件系统控制设备上)
irp请求
*/
NTSTATUS	_FsFilterControlDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
)
{
	PIO_STACK_LOCATION	pIrpStack =
		IoGetCurrentIrpStackLocation( _pIrp );

	PAGED_CODE();

	ASSERT( !IS_MY_CONTROL_DEVICE_OBJECT( _pDeviceObject ) );
	ASSERT( IS_MY_DEVICE_OBJECT( _pDeviceObject ) );

	switch (pIrpStack->MinorFunction)
	{
		//卷挂载请求
		case IRP_MN_MOUNT_VOLUME:
			return	_FsFilterControlMountVolume(
				_pDeviceObject , _pIrp );

			//文件系统识别器收到的加载文件系统的请求
		case IRP_MN_LOAD_FILE_SYSTEM:
			return	_FsFilterControlLoadFileSystem(
				_pDeviceObject , _pIrp );

		case IRP_MN_USER_FS_REQUEST:
			{
				switch (pIrpStack->
					Parameters.FileSystemControl.FsControlCode)
				{
					case FSCTL_DISMOUNT_VOLUME:
						{
							PFSFILTER_DEVICE_EXTENSION pDevExt =
								_pDeviceObject->DeviceExtension;

							//打印信息
							KdPrint( ("_FsFilterControlDispatch:Dismounting volume:\n\
								%p\n%wZ\n" ,
								pDevExt->pLowerFsDeviceObject ,
								&pDevExt->DeviceName) );

							break;
						}
				} // end switch

				break;
			}
	} // end switch (pIrpStack->MinorFunction)

	  //其他Irp请求下发下层设备
	IoSkipCurrentIrpStackLocation( _pIrp );
	return	IoCallDriver(
		((PFSFILTER_DEVICE_EXTENSION)_pDeviceObject->DeviceExtension)->pLowerFsDeviceObject ,
		_pIrp );
}


/*
该函数处理卷挂载请求
通过将挂载请求下发到文件系统,请求处理完后可以获得文件系统创建的
卷设备,然后绑定这个卷设备对象
参数:
自己的过滤设备(绑定在文件系统控制设备之上)
irp请求
*/
NTSTATUS	_FsFilterControlMountVolume(
	IN	PDEVICE_OBJECT	_pFilterControlDevice ,
	IN	PIRP	_pIrp
)
{
	PFSFILTER_DEVICE_EXTENSION	pFilterControlDevExt =
		_pFilterControlDevice->DeviceExtension;
	PIO_STACK_LOCATION	pIrpStack =
		IoGetCurrentIrpStackLocation( _pIrp );
	PDEVICE_OBJECT	pFilterDeviceObject , pStorageStackDeviceObject;
	PFSFILTER_DEVICE_EXTENSION	pFilterDevExt;
	BOOLEAN	bIsShadowCopyVolume;
	NTSTATUS	status;

	PAGED_CODE();

	ASSERT( IS_MY_DEVICE_OBJECT( _pFilterControlDevice ) );
	ASSERT( IS_DESIRED_DEVICE_TYPE( _pFilterControlDevice->DeviceType ) );

	//
	//  Get the real device object (also known as the storage stack device
	//  object or the disk device object) pointed to by the vpb parameter
	//  because this vpb may be changed by the underlying file system.
	//  Both FAT and CDFS may change the VPB address if the volume being
	//  mounted is one they recognize from a previous mount.
	//
	//获得块设备对象
	pStorageStackDeviceObject =
		pIrpStack->Parameters.MountVolume.Vpb->RealDevice;

	//判断是否是一个卷影拷贝设备,不绑定卷影
	status =
		_FsFilterIsShadowCopyVolume(
		pStorageStackDeviceObject ,
		&bIsShadowCopyVolume );
	if (NT_SUCCESS( status ) &&
		bIsShadowCopyVolume)
	{
		//打印卷影设备
		UNICODE_STRING	ShadowDeviceName;
		WCHAR	NameBuffer[64];

		RtlInitEmptyUnicodeString(
			&ShadowDeviceName ,
			NameBuffer ,
			sizeof( NameBuffer ) );

		_FsFilterGetObjectName(
			pStorageStackDeviceObject ,
			&ShadowDeviceName );

		KdPrint( ("_FsFilterControlMountVolume:\n\
			not attach shadow copy volume\n\
			StorageDeviceObject:%p\n\
			Name:%wZ\n " ,
			pStorageStackDeviceObject ,
			&ShadowDeviceName) );

		//将挂载请求下发给文件系统自己处理,不管,这是卷影
		IoSkipCurrentIrpStackLocation( _pIrp );
		return	IoCallDriver(
			pFilterControlDevExt->pLowerFsDeviceObject ,
			_pIrp );

	} // end if (NT_SUCCESS( status ) && bIsShadowCopyVolume)

	  //不是卷影,要绑定

	  //先生成自己的过滤设备(无名),但不绑定vpb中的DeviceObject
	  //因为卷还没有挂载,vpb中的DeviceObject是无效的
	status =
		IoCreateDevice(
		g_pFsFilterDriverObject ,
		sizeof( FSFILTER_DEVICE_EXTENSION ) ,
		NULL ,	//无名
		_pFilterControlDevice->Type ,
		0 ,
		FALSE ,
		&pFilterDeviceObject );
	if (!NT_SUCCESS( status ))
	{
		//如果生成设备失败就不将此挂载请求下发
		//直接完成,返回错误
		KdPrint( ("_FsFilterControlMountVolume:\n\
		Error creating filter device object\n\
		status=%x\n" , status) );

		_pIrp->IoStatus.Information = 0;
		_pIrp->IoStatus.Status = status;
		IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
		return	status;
	}

	//填写设备扩展
	pFilterDevExt = pFilterDeviceObject->DeviceExtension;
	pFilterDevExt->DeviceTag = POOL_TAG;
	pFilterDevExt->pStorageStackDeviceObject = pStorageStackDeviceObject;

	RtlInitEmptyUnicodeString(
		&pFilterDevExt->DeviceName ,
		pFilterDevExt->DeviceNameBuffer ,
		sizeof( pFilterDevExt->DeviceNameBuffer ) );

	_FsFilterGetObjectName(
		pStorageStackDeviceObject ,
		&pFilterDevExt->DeviceName );

	//  On Windows 2000, we cannot simply synchronize back to the dispatch
	//  routine to do our post-mount processing.  We need to do this work at
	//  passive level, so we will queue that work to a worker thread from
	//  the completion routine.
	//
	//  For Windows XP and later, we can safely synchronize back to the dispatch
	//  routine.  The code below shows both methods.  Admittedly, the code
	//  would be simplified if you chose to only use one method or the other, 
	//  but you should be able to easily adapt this for your needs.
	//
	KEVENT	WaitEvent;

	KeInitializeEvent(
		&WaitEvent ,
		NotificationEvent ,
		FALSE );

	IoCopyCurrentIrpStackLocationToNext( _pIrp );

	IoSetCompletionRoutine(
		_pIrp ,
		_FsFilterFsControlCompletion ,
		&WaitEvent ,	//完成函数传入的参数
		TRUE ,
		TRUE ,
		TRUE );

	//发送IRP并等待事件被设置
	status =
		IoCallDriver(
		pFilterControlDevExt->pLowerFsDeviceObject ,
		_pIrp );
	if (status == STATUS_PENDING)
	{
		KeWaitForSingleObject(
			&WaitEvent ,
			Executive ,
			KernelMode ,
			FALSE ,
			NULL );
	}

	/*
	调用函数绑定
	irp会在下面函数中被完成
	如果绑定不成功,新建立的设备会在下面函数里删除
	*/
	status = _FsFilterFsControlMountVolumeComplete(
		//_pFilterControlDevice ,
		_pIrp ,
		pFilterDeviceObject );

	return	status;
}


/*
该完成函数会在文件系统处理完挂载请求后调用
函数将事件对象设置为有信号,等待该事件的代码就会继续执行
参数:
事件类型的指针
*/
NTSTATUS	_FsFilterFsControlCompletion(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp ,
	IN	PVOID	_pContext
)
{
	ASSERT( IS_MY_DEVICE_OBJECT( _pDeviceObject ) );
	ASSERT( _pContext != NULL );

	KeSetEvent(
		(PKEVENT)_pContext ,
		IO_NO_INCREMENT ,
		FALSE );

	//返回STATUS_MORE_PROCESSING_REQUIRED
	//代表该IRP要再次被完成
	return	STATUS_MORE_PROCESSING_REQUIRED;
}


/*
该函数在卷完成挂载后 执行绑定
然后再次完成irp
如果绑定失败会删除新建过滤设备
参数:
Irp请求
新建的过滤设备用来绑定在文件系统卷设备上
返回值:
绑定的结果
*/
NTSTATUS	_FsFilterFsControlMountVolumeComplete(
	//	IN	PDEVICE_OBJECT	_pFilterControlDevice ,
	IN	PIRP	_pIrp ,
	IN	PDEVICE_OBJECT	_pNewFilterDevice
)
{
	PVPB	pvpb;
	PFSFILTER_DEVICE_EXTENSION	pNewDevExt;
	PIO_STACK_LOCATION	pIrpStack;
	PDEVICE_OBJECT	pAttachedDeviceObject;
	NTSTATUS	status;

	PAGED_CODE();

	pNewDevExt = _pNewFilterDevice->DeviceExtension;
	pIrpStack = IoGetCurrentIrpStackLocation( _pIrp );

	//获得之前保存的vpb
	pvpb = pNewDevExt->pStorageStackDeviceObject->Vpb;

	if (NT_SUCCESS( _pIrp->IoStatus.Status ))
	{
		//获得一个互斥体,原子的判断是否绑定过一个设备
		//防止二次绑定
		ExAcquireFastMutex( &g_FastMutexAttach );
		if (!_FsIsAttachedToDevice(
			pvpb->DeviceObject ,
			&pAttachedDeviceObject ))
		{
			//调用完成真正的绑定
			status =
				_FsFilterAttachToMountedDevice(
				pvpb->DeviceObject ,
				_pNewFilterDevice );
			if (!NT_SUCCESS( status ))
			{
				IoDeleteDevice( _pNewFilterDevice );
			}
			ASSERT( pAttachedDeviceObject == NULL );
		} // if (attached)
		else
		{
			//绑定过了
			IoDeleteDevice( _pNewFilterDevice );
			//解除对过滤设备的引用
			ObDereferenceObject( pAttachedDeviceObject );
		} // end if (attached)

		ExReleaseFastMutex( &g_FastMutexAttach );

	} // if (NT_SUCCESS( _pIrp->IoStatus.Status ))
	else
	{
		//到这里说明卷挂载不成功
		IoDeleteDevice( _pNewFilterDevice );
	} // end if(NT_SUCCESS(_pIrp->IoStatus.Status))

	  //再次完成Irp请求
	status = _pIrp->IoStatus.Status;
	IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
	return	status;
}


/*
该函数处理驱动的卸载
要解除对文件系统设备栈的绑定,以及删除设备
参数:
DriverObject自己的驱动对象
*/
VOID	_DriverUnload(
	IN	PDRIVER_OBJECT	_pDriverObject
)
{
	NTSTATUS	status;
	ULONG	i;
	PFSFILTER_DEVICE_EXTENSION	pDevExt;
	PFAST_IO_DISPATCH	pFastIoDispatch;
	ULONG	DevicesCount;
	LARGE_INTEGER	liInterval;
	PDEVICE_OBJECT	pDevList[64];

	ASSERT( _pDriverObject == g_pFsFilterDriverObject );

	KdPrint( ("FsFilter._DriverUnload\n\
			pDriverObject=%p" ,
		_pDriverObject) );

	//取消对文件系统激活的函数回调
	IoUnregisterFsRegistrationChange(
		_pDriverObject ,
		_FsChangeCallback );

	/*
	下面是一个循环
	由于在该函数中避免申请内存,所以一次只能取64个设备对象
	放在数组DevList中,彻底取完就会退出循环
	*/
	for (;;)
	{
		status =
			IoEnumerateDeviceObjectList(
			_pDriverObject ,
			pDevList ,
			sizeof( pDevList ) ,
			&DevicesCount );

		if (DevicesCount <= 0)
			break;

		DevicesCount = min( DevicesCount , 64 );

		/*
		遍历DevList中的设备,解除它们对底层设备的绑定
		但要跳过自己的控制设备,自己的控制设备是用来和应用程序
		通信的,并没有绑定任何设备
		*/
		for (i = 0; i < DevicesCount; i++)
		{
			pDevExt = pDevList[i]->DeviceExtension;
			if (pDevList[i] != g_pFsFilterControlDeviceObject)	//控制设备会跳过
			{
				IoDetachDevice(
					pDevExt->pLowerFsDeviceObject );
			}
		}

		//设置延迟5秒
		liInterval.QuadPart = 5 * DELAY_ONE_SECOND;
		KeDelayExecutionThread(
			KernelMode ,
			FALSE ,
			&liInterval );

		//再次遍历,这次是删除设备
		for (i = 0; i < DevicesCount; i++)
		{
			//判断是否自己的控制设备
			if (pDevList[i] == g_pFsFilterControlDeviceObject)
			{
				PCONTROL_DEVICE_EXTENSION pDevExt =
					pDevList[i]->DeviceExtension;

				if (pDevExt->pUserEvent)
				{ObDereferenceObject( pDevExt->pUserEvent );}
				if(pDevExt->pMdlLog)
				{
					IoFreeMdl( pDevExt->pMdlLog );
				}
				if(pDevExt->pClientLog)
				{
					ExFreePool( pDevExt->pClientLog );
				}
				g_pFsFilterControlDeviceObject = NULL;
			}

			//删除该设备,并且解除由
			//IoEnumerateDeviceObjectList增加的引用
			ObDereferenceObject( pDevList[i] );
			IoDeleteDevice( pDevList[i] );
		}

	} // end for(;;)

	  //还要删除快速io表
	pFastIoDispatch = _pDriverObject->FastIoDispatch;
	_pDriverObject->FastIoDispatch = NULL;
	ExFreePool( pFastIoDispatch );

	//删除符号链接
	UNICODE_STRING	Win32Name;

	RtlInitUnicodeString( &Win32Name , L"\\DosDevices\\PowerfulGun_FsProtect" );
	IoDeleteSymbolicLink( &Win32Name );

	//删除病毒链表
	_DeleteVirusList();

	//关闭注册表子项句柄
	if(g_hRegistrySub)
	ZwClose( g_hRegistrySub );
}


/*
该函数处理设备收到的打开请求,
如果是过滤设备接受到的就尝试打印打开的文件名
参数:
DeviceObject设备对象
pirp请求
*/
NTSTATUS	_FsFilterCreateDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
)
{
	NTSTATUS	status;
	PFSFILTER_DEVICE_EXTENSION	pDevExt =
		_pDeviceObject->DeviceExtension;
	KEVENT	WaitEvent;

	PAGED_CODE();

	//判断是否是自己的控制设备
	if (IS_MY_CONTROL_DEVICE_OBJECT( _pDeviceObject ))
	{
		_pIrp->IoStatus.Status = STATUS_SUCCESS;
		_pIrp->IoStatus.Information = 0;
		IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
		return	STATUS_SUCCESS;
	}

	//不是控制设备就是过滤设备,将请求下发给文件系统去打开
	IoSkipCurrentIrpStackLocation( _pIrp );
	
	return	IoCallDriver(
		(pDevExt->pLowerFsDeviceObject) ,
		_pIrp );
}


/*
该函数处理设备收到的关闭请求
*/
NTSTATUS	_FsFilterCloseDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
)
{
	

	//判断是否是自己的控制设备
	if (IS_MY_CONTROL_DEVICE_OBJECT( _pDeviceObject ))
	{
		PCONTROL_DEVICE_EXTENSION	pDevExt =
			_pDeviceObject->DeviceExtension;

		KdPrint( ("[IRP_MJ_CLOSE]: Close CD0\n") );

		//释放资源
		if (pDevExt->pUserEvent)
		{
			ObDereferenceObject( pDevExt->pUserEvent );
			pDevExt->pUserEvent = NULL;
		}
		if (pDevExt->pMdlLog)
		{
			IoFreeMdl( pDevExt->pMdlLog );
			pDevExt->pMdlLog = NULL;
		}
		if (pDevExt->pClientLog)
		{
			ExFreePool( pDevExt->pClientLog );
			pDevExt->pClientLog = NULL;
		}
		pDevExt->pSharedAddress = NULL;

		//完成irp请求
		_pIrp->IoStatus.Status = STATUS_SUCCESS;
		_pIrp->IoStatus.Information = 0;
		IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
		return	STATUS_SUCCESS;
	}


	PFSFILTER_DEVICE_EXTENSION	pDevExt =
		_pDeviceObject->DeviceExtension;
	//不是自己的控制设备就下发
	IoSkipCurrentIrpStackLocation( _pIrp );

	return IoCallDriver( pDevExt->pLowerFsDeviceObject , _pIrp );

}


/*
该函数当文件系统卸载时解除对文件系统控制设备的引用
参数:
FsControlDevice文件系统控制设备
*/
VOID	_FsFilterDetachFsControlDevice(
	IN	PDEVICE_OBJECT	_pFsControlDevice
)
{
	PDEVICE_OBJECT	pmyFilterDevice;
	PFSFILTER_DEVICE_EXTENSION	pDevExt;

	PAGED_CODE();

	//得到控制设备上方的绑定设备
	//这个绑定设备是自己在文件系统激活的时候绑定的
	pmyFilterDevice = _pFsControlDevice->AttachedDevice;

	while (pmyFilterDevice != NULL)
	{
		if (IS_MY_DEVICE_OBJECT( pmyFilterDevice ))
		{
			pDevExt = pmyFilterDevice->DeviceExtension;

			//打印我们绑定的设备名
			KdPrint( ("_FsFilterDetachFsControlDevice:\n\
			Detaching from FsControlDevice:%p\n\
			DeviceName:%wZ\n\
			DeviceType=%s\n" ,
				pDevExt->pLowerFsDeviceObject ,
				&pDevExt->DeviceName ,
				GET_DEVICE_TYPE_NAME( pmyFilterDevice->DeviceType )) );

			//解除绑定,并删除自己的设备
			IoDetachDevice( _pFsControlDevice );
			IoDeleteDevice( pmyFilterDevice );

			return;
		}

		//可能当前这个过滤设备不是自己的(其他驱动的)
		//继续往上寻找自己的过滤设备然后判断
		_pFsControlDevice = pmyFilterDevice;
		pmyFilterDevice = pmyFilterDevice->AttachedDevice;

	} // end while
}


/*
如果绑定了文件系统识别器,该函数就会处理
文件系统加载的请求,会先下发该请求
请求成功就删除过滤设备
参数:
filterDeviceObject:绑定在文件系统识别器上的过滤设备
PIRP:Irp请求
*/
NTSTATUS	_FsFilterControlLoadFileSystem(
	IN	PDEVICE_OBJECT	_pFilterDeviceObject ,
	IN	PIRP	_pIrp
)
{
	PFSFILTER_DEVICE_EXTENSION	pDevExt =
		_pFilterDeviceObject->DeviceExtension;
	NTSTATUS	status;
	KEVENT	WaitEvent;

	PAGED_CODE();

	KdPrint( ("_FsFilterControlLoadFileSystem:\n\
		Loading file system,detach from %wZ" ,
		&pDevExt->DeviceName) );

	//准备将请求下发
	KeInitializeEvent(
		&WaitEvent ,
		NotificationEvent ,
		FALSE );

	IoCopyCurrentIrpStackLocationToNext( _pIrp );

	IoSetCompletionRoutine(
		_pIrp ,
		_FsFilterFsControlCompletion ,
		&WaitEvent ,
		TRUE ,
		TRUE ,
		TRUE );

	status =
		IoCallDriver(
		pDevExt->pLowerFsDeviceObject ,
		_pIrp );
	//等待请求完成
	if (status == STATUS_PENDING)
	{
		status = KeWaitForSingleObject(
			&WaitEvent ,
			Executive ,
			KernelMode ,
			FALSE ,
			NULL );
		ASSERT( status == STATUS_SUCCESS );
	}
	ASSERT( KeReadStateEvent( &WaitEvent ) ||
		!NT_SUCCESS( _pIrp->IoStatus.Status ) );

	//处理之后的操作,包括完成irp或者删除设备
	status =
		_FsFilterFsControlLoadFileSystemComplete(
		_pFilterDeviceObject , _pIrp );

	return	status;
}


/*
函数处理文件系统加载完成之后的事情,如果文件系统加载成功就删除设备
参数:
filterDeviceObject 识别器上的过滤设备
irp请求
*/
NTSTATUS	_FsFilterFsControlLoadFileSystemComplete(
	IN	PDEVICE_OBJECT	_pFilterDeviceObject ,
	IN	PIRP	_pIrp
)
{
	NTSTATUS	status;
	PFSFILTER_DEVICE_EXTENSION pDevExt =
		_pFilterDeviceObject->DeviceExtension;

	PAGED_CODE();

	//检查irp操作状态
	if (!NT_SUCCESS( _pIrp->IoStatus.Status ) &&
		(_pIrp->IoStatus.Status != STATUS_IMAGE_ALREADY_LOADED))
	{
		//加载失败了就简单地再次绑定控制器
		_FsFilterAttachToDeviceStack(
			_pFilterDeviceObject ,
			pDevExt->pLowerFsDeviceObject ,
			&pDevExt->pLowerFsDeviceObject );
		ASSERT( pDevExt->pLowerFsDeviceObject != NULL );
	}
	else
	{
		//加载成功的情况下就删除设备
		IoDeleteDevice( _pFilterDeviceObject );
	}

	//完成Irp请求
	status = _pIrp->IoStatus.Status;

	IoCompleteRequest( _pIrp , IO_NO_INCREMENT );

	return	status;
}

/////////////////////////////////////////////////////////////////////////////
//
//                      FastIO Handling routines
//
/////////////////////////////////////////////////////////////////////////////

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
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for checking to see
whether fast I/O is possible for this file.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

FileObject - Pointer to the file object to be operated on.

FileOffset - Byte offset in the file for the operation.

Length - Length of the operation to be performed.

Wait - Indicates whether or not the caller is willing to wait if the
appropriate locks, etc. cannot be acquired

LockKey - Provides the caller's key for file locks.

CheckForReadOperation - Indicates whether the caller is checking for a
read (TRUE) or a write operation.

IoStatus - Pointer to a variable to receive the I/O status of the
operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	// return FALSE;	// add by tanwen.

	// 如果是控制设备，不允许
	if (IS_MY_CONTROL_DEVICE_OBJECT( DeviceObject ))
		return FALSE;
	// 如果不是我的设备(影子设备可能发生这种情况)    
	if (!IS_MY_DEVICE_OBJECT( DeviceObject ))
		return FALSE;


	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , FastIoCheckIfPossible )) {

			return (fastIoDispatch->FastIoCheckIfPossible)(
				FileObject ,
				FileOffset ,
				Length ,
				Wait ,
				LockKey ,
				CheckForReadOperation ,
				IoStatus ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


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
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for reading from a
file.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

FileObject - Pointer to the file object to be read.

FileOffset - Byte offset in the file of the read.

Length - Length of the read operation to be performed.

Wait - Indicates whether or not the caller is willing to wait if the
appropriate locks, etc. cannot be acquired

LockKey - Provides the caller's key for file locks.

Buffer - Pointer to the caller's buffer to receive the data read.

IoStatus - Pointer to a variable to receive the I/O status of the
operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	return FALSE;	// add by tanwen.

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , FastIoRead )) {

			return (fastIoDispatch->FastIoRead)(
				FileObject ,
				FileOffset ,
				Length ,
				Wait ,
				LockKey ,
				Buffer ,
				IoStatus ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


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
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for writing to a
file.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

FileObject - Pointer to the file object to be written.

FileOffset - Byte offset in the file of the write operation.

Length - Length of the write operation to be performed.

Wait - Indicates whether or not the caller is willing to wait if the
appropriate locks, etc. cannot be acquired

LockKey - Provides the caller's key for file locks.

Buffer - Pointer to the caller's buffer that contains the data to be
written.

IoStatus - Pointer to a variable to receive the I/O status of the
operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	return FALSE;	// add by tanwen.

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , FastIoWrite )) {

			return (fastIoDispatch->FastIoWrite)(
				FileObject ,
				FileOffset ,
				Length ,
				Wait ,
				LockKey ,
				Buffer ,
				IoStatus ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


BOOLEAN
_FastIoQueryBasicInfo(
	IN PFILE_OBJECT FileObject ,
	IN BOOLEAN Wait ,
	OUT PFILE_BASIC_INFORMATION Buffer ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for querying basic
information about the file.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

FileObject - Pointer to the file object to be queried.

Wait - Indicates whether or not the caller is willing to wait if the
appropriate locks, etc. cannot be acquired

Buffer - Pointer to the caller's buffer to receive the information about
the file.

IoStatus - Pointer to a variable to receive the I/O status of the
operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	return FALSE;	// add by tanwen.

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , FastIoQueryBasicInfo )) {

			return (fastIoDispatch->FastIoQueryBasicInfo)(
				FileObject ,
				Wait ,
				Buffer ,
				IoStatus ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


BOOLEAN
_FastIoQueryStandardInfo(
	IN PFILE_OBJECT FileObject ,
	IN BOOLEAN Wait ,
	OUT PFILE_STANDARD_INFORMATION Buffer ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for querying standard
information about the file.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

FileObject - Pointer to the file object to be queried.

Wait - Indicates whether or not the caller is willing to wait if the
appropriate locks, etc. cannot be acquired

Buffer - Pointer to the caller's buffer to receive the information about
the file.

IoStatus - Pointer to a variable to receive the I/O status of the
operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	return FALSE;

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , FastIoQueryStandardInfo )) {

			return (fastIoDispatch->FastIoQueryStandardInfo)(
				FileObject ,
				Wait ,
				Buffer ,
				IoStatus ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


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
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for locking a byte
range within a file.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

FileObject - Pointer to the file object to be locked.

FileOffset - Starting byte offset from the base of the file to be locked.

Length - Length of the byte range to be locked.

ProcessId - ID of the process requesting the file lock.

Key - Lock key to associate with the file lock.

FailImmediately - Indicates whether or not the lock request is to fail
if it cannot be immediately be granted.

ExclusiveLock - Indicates whether the lock to be taken is exclusive (TRUE)
or shared.

IoStatus - Pointer to a variable to receive the I/O status of the
operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	return FALSE;	// add by tanwen.

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , FastIoLock )) {

			return (fastIoDispatch->FastIoLock)(
				FileObject ,
				FileOffset ,
				Length ,
				ProcessId ,
				Key ,
				FailImmediately ,
				ExclusiveLock ,
				IoStatus ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


BOOLEAN
_FastIoUnlockSingle(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN PLARGE_INTEGER Length ,
	PEPROCESS ProcessId ,
	ULONG Key ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for unlocking a byte
range within a file.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

FileObject - Pointer to the file object to be unlocked.

FileOffset - Starting byte offset from the base of the file to be
unlocked.

Length - Length of the byte range to be unlocked.

ProcessId - ID of the process requesting the unlock operation.

Key - Lock key associated with the file lock.

IoStatus - Pointer to a variable to receive the I/O status of the
operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	return FALSE;	// add by tanwen.

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , FastIoUnlockSingle )) {

			return (fastIoDispatch->FastIoUnlockSingle)(
				FileObject ,
				FileOffset ,
				Length ,
				ProcessId ,
				Key ,
				IoStatus ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


BOOLEAN
_FastIoUnlockAll(
	IN PFILE_OBJECT FileObject ,
	PEPROCESS ProcessId ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for unlocking all
locks within a file.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

FileObject - Pointer to the file object to be unlocked.

ProcessId - ID of the process requesting the unlock operation.

IoStatus - Pointer to a variable to receive the I/O status of the
operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	return FALSE;	// add by tanwen.

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;

		if (nextDeviceObject) {

			fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

			if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , FastIoUnlockAll )) {

				return (fastIoDispatch->FastIoUnlockAll)(
					FileObject ,
					ProcessId ,
					IoStatus ,
					nextDeviceObject);
			}
		}
	}
	return FALSE;
}


BOOLEAN
_FastIoUnlockAllByKey(
	IN PFILE_OBJECT FileObject ,
	PVOID ProcessId ,
	ULONG Key ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for unlocking all
locks within a file based on a specified key.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

FileObject - Pointer to the file object to be unlocked.

ProcessId - ID of the process requesting the unlock operation.

Key - Lock key associated with the locks on the file to be released.

IoStatus - Pointer to a variable to receive the I/O status of the
operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	return FALSE;	// add by tanwen.

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , FastIoUnlockAllByKey )) {

			return (fastIoDispatch->FastIoUnlockAllByKey)(
				FileObject ,
				ProcessId ,
				Key ,
				IoStatus ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


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
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for device I/O control
operations on a file.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

FileObject - Pointer to the file object representing the device to be
serviced.

Wait - Indicates whether or not the caller is willing to wait if the
appropriate locks, etc. cannot be acquired

InputBuffer - Optional pointer to a buffer to be passed into the driver.

InputBufferLength - Length of the optional InputBuffer, if one was
specified.

OutputBuffer - Optional pointer to a buffer to receive data from the
driver.

OutputBufferLength - Length of the optional OutputBuffer, if one was
specified.

IoControlCode - I/O control code indicating the operation to be performed
on the device.

IoStatus - Pointer to a variable to receive the I/O status of the
operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	if (IS_MY_CONTROL_DEVICE_OBJECT( DeviceObject ))
		return FALSE;
	// 如果不是我的设备(影子设备可能发生这种情况)    
	if (!IS_MY_DEVICE_OBJECT( DeviceObject ))
		return FALSE;

	//	return FALSE;	 // add by tanwen.	有趣的是，这个操作不可以返回false。如果
	// 返回了false，会导致金蝶启动狂慢无比（有时启动时间达15分钟以上）。
	// 如果是控制设备，不允许

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , FastIoDeviceControl )) {

			return (fastIoDispatch->FastIoDeviceControl)(
				FileObject ,
				Wait ,
				InputBuffer ,
				InputBufferLength ,
				OutputBuffer ,
				OutputBufferLength ,
				IoControlCode ,
				IoStatus ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


VOID
_FastIoDetachDevice(
	IN PDEVICE_OBJECT SourceDevice ,
	IN PDEVICE_OBJECT TargetDevice
)

/*++

Routine Description:

This routine is invoked on the fast path to detach from a device that
is being deleted.  This occurs when this driver has attached to a file
system volume device object, and then, for some reason, the file system
decides to delete that device (it is being dismounted, it was dismounted
at some point in the past and its last reference has just gone away, etc.)

Arguments:

SourceDevice - Pointer to my device object, which is attached
to the file system's volume device object.

TargetDevice - Pointer to the file system's volume device object.

Return Value:

None

--*/

{
	PFSFILTER_DEVICE_EXTENSION devExt;

	PAGED_CODE();

	ASSERT( IS_MY_DEVICE_OBJECT( SourceDevice ) );

	devExt = SourceDevice->DeviceExtension;

	//
	//  Display name information
	//

	KdPrint( ("FastIoDetachDevice:\n\
			Detaching from volume      %p \"%wZ\"\n" ,
		TargetDevice ,
		&devExt->DeviceName) );

	//
	//  Detach from the file system's volume device object.
	//

	IoDetachDevice( TargetDevice );
	IoDeleteDevice( SourceDevice );
}


BOOLEAN
_FastIoQueryNetworkOpenInfo(
	IN PFILE_OBJECT FileObject ,
	IN BOOLEAN Wait ,
	OUT PFILE_NETWORK_OPEN_INFORMATION Buffer ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for querying network
information about a file.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

FileObject - Pointer to the file object to be queried.

Wait - Indicates whether or not the caller can handle the file system
having to wait and tie up the current thread.

Buffer - Pointer to a buffer to receive the network information about the
file.

IoStatus - Pointer to a variable to receive the final status of the query
operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	return FALSE;			// ERPOK

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , FastIoQueryNetworkOpenInfo )) {

			return (fastIoDispatch->FastIoQueryNetworkOpenInfo)(
				FileObject ,
				Wait ,
				Buffer ,
				IoStatus ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


BOOLEAN
_FastIoMdlRead(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN ULONG Length ,
	IN ULONG LockKey ,
	OUT PMDL *MdlChain ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for reading a file
using MDLs as buffers.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

FileObject - Pointer to the file object that is to be read.

FileOffset - Supplies the offset into the file to begin the read operation.

Length - Specifies the number of bytes to be read from the file.

LockKey - The key to be used in byte range lock checks.

MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
chain built to describe the data read.

IoStatus - Variable to receive the final status of the read operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	return FALSE; // ERPOK

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , MdlRead )) {

			return (fastIoDispatch->MdlRead)(
				FileObject ,
				FileOffset ,
				Length ,
				LockKey ,
				MdlChain ,
				IoStatus ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


BOOLEAN
_FastIoMdlReadComplete(
	IN PFILE_OBJECT FileObject ,
	IN PMDL MdlChain ,
	IN PDEVICE_OBJECT DeviceObject
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for completing an
MDL read operation.

This function simply invokes the file system's corresponding routine, if
it has one.  It should be the case that this routine is invoked only if
the MdlRead function is supported by the underlying file system, and
therefore this function will also be supported, but this is not assumed
by this driver.

Arguments:

FileObject - Pointer to the file object to complete the MDL read upon.

MdlChain - Pointer to the MDL chain used to perform the read operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE, depending on whether or not it is
possible to invoke this function on the fast I/O path.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	return FALSE; // ERPOK

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , MdlReadComplete )) {

			return (fastIoDispatch->MdlReadComplete)(
				FileObject ,
				MdlChain ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


BOOLEAN
_FastIoPrepareMdlWrite(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN ULONG Length ,
	IN ULONG LockKey ,
	OUT PMDL *MdlChain ,
	OUT PIO_STATUS_BLOCK IoStatus ,
	IN PDEVICE_OBJECT DeviceObject
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for preparing for an
MDL write operation.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

FileObject - Pointer to the file object that will be written.

FileOffset - Supplies the offset into the file to begin the write operation.

Length - Specifies the number of bytes to be write to the file.

LockKey - The key to be used in byte range lock checks.

MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
chain built to describe the data written.

IoStatus - Variable to receive the final status of the write operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	return FALSE; // ERPOK

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , PrepareMdlWrite )) {

			return (fastIoDispatch->PrepareMdlWrite)(
				FileObject ,
				FileOffset ,
				Length ,
				LockKey ,
				MdlChain ,
				IoStatus ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


BOOLEAN
_FastIoMdlWriteComplete(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN PMDL MdlChain ,
	IN PDEVICE_OBJECT DeviceObject
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for completing an
MDL write operation.

This function simply invokes the file system's corresponding routine, if
it has one.  It should be the case that this routine is invoked only if
the PrepareMdlWrite function is supported by the underlying file system,
and therefore this function will also be supported, but this is not
assumed by this driver.

Arguments:

FileObject - Pointer to the file object to complete the MDL write upon.

FileOffset - Supplies the file offset at which the write took place.

MdlChain - Pointer to the MDL chain used to perform the write operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE, depending on whether or not it is
possible to invoke this function on the fast I/O path.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	return FALSE; // ERPOK

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , MdlWriteComplete )) {

			return (fastIoDispatch->MdlWriteComplete)(
				FileObject ,
				FileOffset ,
				MdlChain ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


/*********************************************************************************
UNIMPLEMENTED FAST IO ROUTINES

The following four Fast IO routines are for compression on the wire
which is not yet implemented in NT.

NOTE:  It is highly recommended that you include these routines (which
do a pass-through call) so your filter will not need to be
modified in the future when this functionality is implemented in
the OS.

FastIoReadCompressed, FastIoWriteCompressed,
FastIoMdlReadCompleteCompressed, FastIoMdlWriteCompleteCompressed
**********************************************************************************/


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
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for reading compressed
data from a file.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

FileObject - Pointer to the file object that will be read.

FileOffset - Supplies the offset into the file to begin the read operation.

Length - Specifies the number of bytes to be read from the file.

LockKey - The key to be used in byte range lock checks.

Buffer - Pointer to a buffer to receive the compressed data read.

MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
chain built to describe the data read.

IoStatus - Variable to receive the final status of the read operation.

CompressedDataInfo - A buffer to receive the description of the compressed
data.

CompressedDataInfoLength - Specifies the size of the buffer described by
the CompressedDataInfo parameter.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	return FALSE; 		// ERPOK

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , FastIoReadCompressed )) {

			return (fastIoDispatch->FastIoReadCompressed)(
				FileObject ,
				FileOffset ,
				Length ,
				LockKey ,
				Buffer ,
				MdlChain ,
				IoStatus ,
				CompressedDataInfo ,
				CompressedDataInfoLength ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


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
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for writing compressed
data to a file.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

FileObject - Pointer to the file object that will be written.

FileOffset - Supplies the offset into the file to begin the write operation.

Length - Specifies the number of bytes to be write to the file.

LockKey - The key to be used in byte range lock checks.

Buffer - Pointer to the buffer containing the data to be written.

MdlChain - A pointer to a variable to be filled in w/a pointer to the MDL
chain built to describe the data written.

IoStatus - Variable to receive the final status of the write operation.

CompressedDataInfo - A buffer to containing the description of the
compressed data.

CompressedDataInfoLength - Specifies the size of the buffer described by
the CompressedDataInfo parameter.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	PAGED_CODE();

	return FALSE; 		// ERPOK

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , FastIoWriteCompressed )) {

			return (fastIoDispatch->FastIoWriteCompressed)(
				FileObject ,
				FileOffset ,
				Length ,
				LockKey ,
				Buffer ,
				MdlChain ,
				IoStatus ,
				CompressedDataInfo ,
				CompressedDataInfoLength ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


BOOLEAN
_FastIoMdlReadCompleteCompressed(
	IN PFILE_OBJECT FileObject ,
	IN PMDL MdlChain ,
	IN PDEVICE_OBJECT DeviceObject
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for completing an
MDL read compressed operation.

This function simply invokes the file system's corresponding routine, if
it has one.  It should be the case that this routine is invoked only if
the read compressed function is supported by the underlying file system,
and therefore this function will also be supported, but this is not assumed
by this driver.

Arguments:

FileObject - Pointer to the file object to complete the compressed read
upon.

MdlChain - Pointer to the MDL chain used to perform the read operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE, depending on whether or not it is
possible to invoke this function on the fast I/O path.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	return FALSE; 		// ERPOK

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , MdlReadCompleteCompressed )) {

			return (fastIoDispatch->MdlReadCompleteCompressed)(
				FileObject ,
				MdlChain ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


BOOLEAN
_FastIoMdlWriteCompleteCompressed(
	IN PFILE_OBJECT FileObject ,
	IN PLARGE_INTEGER FileOffset ,
	IN PMDL MdlChain ,
	IN PDEVICE_OBJECT DeviceObject
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for completing a
write compressed operation.

This function simply invokes the file system's corresponding routine, if
it has one.  It should be the case that this routine is invoked only if
the write compressed function is supported by the underlying file system,
and therefore this function will also be supported, but this is not assumed
by this driver.

Arguments:

FileObject - Pointer to the file object to complete the compressed write
upon.

FileOffset - Supplies the file offset at which the file write operation
began.

MdlChain - Pointer to the MDL chain used to perform the write operation.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE, depending on whether or not it is
possible to invoke this function on the fast I/O path.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;

	return FALSE; 		// ERPOK

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , MdlWriteCompleteCompressed )) {

			return (fastIoDispatch->MdlWriteCompleteCompressed)(
				FileObject ,
				FileOffset ,
				MdlChain ,
				nextDeviceObject);
		}
	}
	return FALSE;
}


BOOLEAN
_FastIoQueryOpen(
	IN PIRP Irp ,
	OUT PFILE_NETWORK_OPEN_INFORMATION NetworkInformation ,
	IN PDEVICE_OBJECT DeviceObject
)

/*++

Routine Description:

This routine is the fast I/O "pass through" routine for opening a file
and returning network information for it.

This function simply invokes the file system's corresponding routine, or
returns FALSE if the file system does not implement the function.

Arguments:

Irp - Pointer to a create IRP that represents this open operation.  It is
to be used by the file system for common open/create code, but not
actually completed.

NetworkInformation - A buffer to receive the information required by the
network about the file being opened.

DeviceObject - Pointer to this driver's device object, the device on
which the operation is to occur.

Return Value:

The function value is TRUE or FALSE based on whether or not fast I/O
is possible for this file.

--*/

{
	PDEVICE_OBJECT nextDeviceObject;
	PFAST_IO_DISPATCH fastIoDispatch;
	BOOLEAN result;

	PAGED_CODE();

	return FALSE;			// ERPOK

	if (DeviceObject->DeviceExtension) {

		ASSERT( IS_MY_DEVICE_OBJECT( DeviceObject ) );

		//
		//  Pass through logic for this type of Fast I/O
		//

		nextDeviceObject = ((PFSFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension)->pLowerFsDeviceObject;
		ASSERT( nextDeviceObject );

		fastIoDispatch = nextDeviceObject->DriverObject->FastIoDispatch;

		if (VALID_FAST_IO_DISPATCH_HANDLER( fastIoDispatch , FastIoQueryOpen )) {

			PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation( Irp );

			//
			//  Before calling the next filter, we must make sure their device
			//  object is in the current stack entry for the given IRP
			//

			irpSp->DeviceObject = nextDeviceObject;

			result = (fastIoDispatch->FastIoQueryOpen)(
				Irp ,
				NetworkInformation ,
				nextDeviceObject);

			//
			//  Always restore the IRP back to our device object
			//

			irpSp->DeviceObject = DeviceObject;
			return result;
		}
	}
	return FALSE;
}


/*
该完成函数会在文件系统完成Create IRp请求后调用
函数里设置事件为有信号
*/
NTSTATUS	_FsFilterCreateCompletion(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp ,
	IN	PVOID	_pContext
)
{
	PKEVENT	pWaitEvent = _pContext;

	UNREFERENCED_PARAMETER( _pDeviceObject );
	UNREFERENCED_PARAMETER( _pIrp );

	ASSERT( IS_MY_DEVICE_OBJECT( _pDeviceObject ) );

	//设置事件
	KeSetEvent( pWaitEvent , IO_NO_INCREMENT , FALSE );

	return	STATUS_MORE_PROCESSING_REQUIRED;
}


/*
该函数根据需要打印请求中的文件对象的文件名
参数:
pIrp请求
pFirstDisplayStr需要优先打印的字符串
pSuffix需要匹配的文件后缀名,如果该文件名的后缀匹配才会打印
pbIsExe用来返回该文件名是否是一个可执行文件(后缀是exe或dll)
*/
NTSTATUS	_FsFilterDisplayFileName(
	IN	PIRP	_pIrp,
	IN OPTIONAL PWCHAR	_pFirstDisplayStr,
	IN OPTIONAL	PSUFFIX	_pSuffix,
	OUT OPTIONAL PBOOLEAN	_pbIsExe
)
{
	PIO_STACK_LOCATION	pIrpStack;
	PFILE_OBJECT	pFileObject = NULL;
	PWCHAR	pNameBuffer = NULL;


	pIrpStack = IoGetCurrentIrpStackLocation( _pIrp );
	pFileObject = pIrpStack->FileObject;
	if (_pbIsExe)
		*_pbIsExe = FALSE;

	if (pFileObject->FileName.Length > 0)
	{
		if (_pSuffix == NULL)
		{	//不用匹配后缀直接打印
			KdPrint( ("%S\tFileObject->FileName:%wZ\n" ,
				_pFirstDisplayStr,&pFileObject->FileName) );

			return STATUS_SUCCESS;
		}
		
		if (pFileObject->FileName.Length > 4 * 2)
		{
			//因为pFileObject->FileName->buffer中的字符串不是以\0结尾,所以要
			//将文件名拷贝到自己的缓冲区(以\0结尾)中,为了之后使用wcstr函数
			pNameBuffer =
				ExAllocatePoolWithTag(
				NonPagedPool ,
				pFileObject->FileName.Length + sizeof( WCHAR ) ,	//加一末尾\0
				POOL_TAG );
			if (pNameBuffer == NULL)
				return	STATUS_INSUFFICIENT_RESOURCES;

			RtlZeroMemory( pNameBuffer ,
				pFileObject->FileName.Length + sizeof( WCHAR ) );
			wcsncpy(
				pNameBuffer ,
				pFileObject->FileName.Buffer ,
				pFileObject->FileName.Length / sizeof( WCHAR ) );

			//在文件名中匹配后缀字符串
			for (ULONG i = 0; _pSuffix[i].SuffixLength != 0; i++)
			{
				if (wcsstr(					//注意wcstr
					pNameBuffer ,			//如果该参数字符串不是以\0结尾,该函数调用有时会蓝屏(内存访问违规)
					_pSuffix[i].pSuffix ))
				{
					KdPrint( ("%S\tFileObject->FileName:%wZ\n" ,
						_pFirstDisplayStr , &pFileObject->FileName) );

					//输出日志
					if (((PCONTROL_DEVICE_EXTENSION)
						(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog)
					{
						((PCONTROL_DEVICE_EXTENSION)
							(g_pFsFilterControlDeviceObject->DeviceExtension))->
							pClientLog->
							CharCounts =
							swprintf(
							((PCONTROL_DEVICE_EXTENSION)
							(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog->LogBuffer ,
							L"\r\n%s\r\nFileObject->FileName:%wZ\r\n", _pFirstDisplayStr , &pFileObject->FileName );

						KeSetEvent(
							((PCONTROL_DEVICE_EXTENSION)
							(g_pFsFilterControlDeviceObject->DeviceExtension))->pUserEvent ,
							IO_NO_INCREMENT ,
							FALSE );
					}
				}
			} // end for
			ExFreePool( pNameBuffer );
		} // if (pFileObject->FileName.Length > 4 * 2)

		//通过检查后缀名判断是否是一个可执行文件
		if (pFileObject->FileName.Length > 4 * 2)
		{
			ULONG	SuffixOffset = pFileObject->FileName.Length / sizeof( WCHAR );
			if ((pFileObject->FileName.Buffer[SuffixOffset - 1] == L'e' &&
				pFileObject->FileName.Buffer[SuffixOffset - 2] == L'x' &&
				pFileObject->FileName.Buffer[SuffixOffset - 3] == L'e' &&
				pFileObject->FileName.Buffer[SuffixOffset - 4] == L'.')
				||
				(pFileObject->FileName.Buffer[SuffixOffset - 1] == L'l' &&
				pFileObject->FileName.Buffer[SuffixOffset - 2] == L'l' &&
				pFileObject->FileName.Buffer[SuffixOffset - 3] == L'd' &&
				pFileObject->FileName.Buffer[SuffixOffset - 4] == L'.'))
				if (_pbIsExe)
					*_pbIsExe = TRUE;

		}
	} // if (pFileObject->FileName.Length > 0)
	else
	{
		//该文件对象没有文件名,可能是c:  d:之类的驱动器对象
		//KdPrint( ("%S\tNo File Name\n",_pFirstDisplayStr) );
	}


	return	STATUS_SUCCESS;
	/*
	第一次调用,传入参数0,目的为了获得名称字节大小
	status = ObQueryNameString(
	pFileObject ,
	pNameInfor ,
	Length ,
	&Length );
	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
	Length += 16;
	分配长度
	pNameBuffer = ExAllocatePoolWithTag(
	NonPagedPool ,
	Length,
	POOL_TAG );
	if (pNameBuffer == NULL)
	{
	KdPrint( ("_FsFilterDisplayFileName.ExAllocatePoolTag fail\n") );

	return;
	}

	第二次调用
	pNameInfor = (POBJECT_NAME_INFORMATION)pNameBuffer;
	status = ObQueryNameString(
	pFileObject ,
	pNameInfor ,
	Length ,
	&Length );
	if (NT_SUCCESS( status ) && pNameInfor->Name.Length )
	{
	KdPrint( ("FileName:%wZ\n" ,
	&pNameInfor->Name) );
	*/
}


/*
该函数处理IRP_MJ_READ请求
主要监控是否有对exe文件读的情况
*/
NTSTATUS	_FsFilterReadDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
)
{
	NTSTATUS	status;
	PIO_STACK_LOCATION	pIrpStack =
		IoGetCurrentIrpStackLocation( _pIrp );
	PFILE_OBJECT	pFileObject = pIrpStack->FileObject;
	PFSFILTER_DEVICE_EXTENSION	pDevExt =
		_pDeviceObject->DeviceExtension;
	BOOLEAN	bIsVirus = FALSE;
	BOOLEAN	bIsExeProgram=FALSE;
	SUFFIX	Suffix[] = {
		L".exe",4 * 2,
		L".dll",4 * 2 ,
		NULL,0 };

	do
	{
	//如果是自己的控制设备收到的
		if (IS_MY_CONTROL_DEVICE_OBJECT( _pDeviceObject ))
		{
			//返回不支持
			_pIrp->IoStatus.Information = 0;
			_pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
			IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
			return	STATUS_NOT_SUPPORTED;
		}

		//先查看控制器中读请求是否要过滤
		if (g_Control.ReadControl == FALSE)
			break;

		//判断目标文件是否是exe文件并输出符合特定后缀的文件名
		status = _FsFilterDisplayFileName(
			_pIrp ,
			L"[IRP_MJ_READ]\n" ,
			Suffix ,
			&bIsExeProgram );

		//判断此次操作是否需要放行
		if (pFileObject->FsContext == g_pSkipFileObjectContext)
		{
			KdPrint( ("Skip check this fileobject\n") );
			break;
		}

		//如果是可执行文件需要进一步检查
		if (bIsExeProgram == TRUE &&
			NT_SUCCESS( status ))
		{
			//检查正要读的可执行文件是否有病毒特征码
			status = _CheckVirusFile(
				NULL ,
				pFileObject ,
				_pDeviceObject ,
				&bIsVirus );
			if (NT_SUCCESS( status ) && bIsVirus == TRUE)
			{
				//是病毒,删除目标病毒文件
				FILE_DISPOSITION_INFORMATION	FileDispositionInfor;
				FileDispositionInfor.DeleteFile = TRUE;

				status = _IrpSetFileInformation(
					pFileObject->Vpb->DeviceObject ,
					pFileObject ,
					FileDispositionInformation ,
					&FileDispositionInfor ,
					sizeof( FILE_DISPOSITION_INFORMATION ) );
				if (!NT_SUCCESS( status ))
				{
					KdPrint( ("_CheckVirusFile.\n\
							\t_IrpSetFileInformation fail,status=%x\n" , status) );
				}

				KdPrint( ("###################\n\
							Delete it !\n\
							####################\n") );

				KdPrint( ("##################\n\
						 \tNo read it !\n\
						  ##################\n") );
				//输出日志
				if (((PCONTROL_DEVICE_EXTENSION)
					(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog)
				{
					((PCONTROL_DEVICE_EXTENSION)
						(g_pFsFilterControlDeviceObject->DeviceExtension))->
						pClientLog->
						CharCounts =
						swprintf(
						((PCONTROL_DEVICE_EXTENSION)
						(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog->LogBuffer ,
						L"###################\r\nDelete it !\r\n####################\r\n\r\n##################\r\n\tNo read it !\r\n##################\r\n");

					KeSetEvent(
						((PCONTROL_DEVICE_EXTENSION)
						(g_pFsFilterControlDeviceObject->DeviceExtension))->pUserEvent ,
						IO_NO_INCREMENT ,
						FALSE );
				}

			//直接结束Irp请求,不给文件系统读取
				status = STATUS_FILE_CLOSED;
				_pIrp->IoStatus.Status = status;
				_pIrp->IoStatus.Information = 0;
				IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
				return	status;
			}
		} // end if
	} while (FALSE);

	//正常给文件系统去读取
	IoSkipCurrentIrpStackLocation( _pIrp );
	return	IoCallDriver(
		pDevExt->pLowerFsDeviceObject ,
		_pIrp );
}


/*
该函数检查目标exe程序是否有病毒特征码
参数:
hFile相关的文件句柄
pFileObject相关的文件对象
pDeviceObject过滤设备对象
pbIsVirus用来返回是否是病毒
*/
NTSTATUS	_CheckVirusFile(
	IN OPTIONAL	HANDLE	_hFile,
	IN	PFILE_OBJECT	_pFileObject ,
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	OUT	PBOOLEAN	_pbIsVirus
)
{
	PFSFILTER_DEVICE_EXTENSION	pDevExt =
		_pDeviceObject->DeviceExtension;
	NTSTATUS	status = STATUS_SUCCESS;
	ULONG	FileData[4];

	do
	{	//判断当前文件对象是否已经检查过
		if (g_LastFileContext.pFsContext == _pFileObject->FsContext)
		{
			KdPrint( ("This File had read\n") );
			*_pbIsVirus = g_LastFileContext.bIsVirus;
			break;
		}
		else
		{
			KdPrint( ("Find an new File,start read file data.\n") );
			g_LastFileContext.pFsContext = _pFileObject->FsContext;

		}

		//获取文件特征码
		status =
			_FsFilterGetFileData(
			_hFile,
			_pFileObject ,
			pDevExt->pLowerFsDeviceObject ,
			FileData );
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("_CheckVirusFile._FsFilterGetFileData fail,\
				status=%x\n" , status) );
			g_LastFileContext.pFsContext = NULL;

			break;
		}
		//打印文件特征码
		KdPrint( ("FileData[0]:%x\n\
				FileData[1]:%x\n\
				FileData[2]:%x\n\
				FileData[3]:%x\n" ,
			FileData[0] , FileData[1] , FileData[2] , FileData[3]) );
		//将文件特征码记录进LastFileContext,作为最近一次分析操作
		g_LastFileContext.FileData[0] = FileData[0];
		g_LastFileContext.FileData[1] = FileData[1];
		g_LastFileContext.FileData[2] = FileData[2];
		g_LastFileContext.FileData[3] = FileData[3];

		//输出日志
		if (((PCONTROL_DEVICE_EXTENSION)
			(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog)
		{
			((PCONTROL_DEVICE_EXTENSION)
				(g_pFsFilterControlDeviceObject->DeviceExtension))->
				pClientLog->
				CharCounts =
				swprintf(
				((PCONTROL_DEVICE_EXTENSION)
				(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog->LogBuffer ,
				L"FileData[0]:%x\r\nFileData[1]:%x\r\nFileData[2]:%x\r\nFileData[3]:%x\r\n" , \
				FileData[0] , FileData[1] , FileData[2] , FileData[3] );

			KeSetEvent(
				((PCONTROL_DEVICE_EXTENSION)
				(g_pFsFilterControlDeviceObject->DeviceExtension))->pUserEvent ,
				IO_NO_INCREMENT ,
				FALSE );
		}

		*_pbIsVirus = FALSE;
		g_LastFileContext.bIsVirus = FALSE;
		//判断是否是病毒
		PVIRUS_LIST pTempVirusList;
		for (pTempVirusList = (PVIRUS_LIST)g_VirusListHead.Flink;
			pTempVirusList != (PVIRUS_LIST)&g_VirusListHead; 
			pTempVirusList = (PVIRUS_LIST)pTempVirusList->ListEntry.Flink)
		{
			if (FileData[0] == pTempVirusList->VirusInfor.FileData[0] &&
				FileData[1] == pTempVirusList->VirusInfor.FileData[1] &&
				FileData[2] == pTempVirusList->VirusInfor.FileData[2] &&
				FileData[3] == pTempVirusList->VirusInfor.FileData[3])
			{
				//特征码和本地保存的一样就是病毒
				*_pbIsVirus = TRUE;
				g_LastFileContext.bIsVirus = TRUE;

				KdPrint( ("###################\n\
							Find Virus:\t%S\n\
							####################\n" , pTempVirusList->VirusInfor.Name) );
				//输出日志
				if (((PCONTROL_DEVICE_EXTENSION)
					(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog)
				{
					((PCONTROL_DEVICE_EXTENSION)
						(g_pFsFilterControlDeviceObject->DeviceExtension))->
						pClientLog->
						CharCounts =
						swprintf(
						((PCONTROL_DEVICE_EXTENSION)
						(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog->LogBuffer ,
						L"###################\r\nFind Virus:\t%s\r\n####################\r\n" , \
						pTempVirusList->VirusInfor.Name );

					KeSetEvent(
						((PCONTROL_DEVICE_EXTENSION)
						(g_pFsFilterControlDeviceObject->DeviceExtension))->pUserEvent ,
						IO_NO_INCREMENT ,
						FALSE );
				}

				break;
			}
		}

	} while (FALSE);

	return	status;
}


/*
该函数查询文件信息
参数:
pFileOebjct相关的文件对象
pLowerDeviceObject 过滤设备下层的文件系统的设备
FILE_INFORMATION_CLASS请求查询的类别
pBuffer用来返回查询的结果的缓冲区
BufferLength 缓冲区的大小
*/
NTSTATUS	_IrpQueryFileInformation(
	IN	PFILE_OBJECT	_pFileObject ,
	IN	PDEVICE_OBJECT	_pFsDeviceObject ,
	IN	FILE_INFORMATION_CLASS _InforClass ,
	OUT	PVOID	_pBuffer ,
	IN	ULONG	_BufferLength
)
{
	KEVENT	WaitEvent;
	PIRP	pIrp = NULL;
	IO_STATUS_BLOCK	iosb;
	PIO_STACK_LOCATION	pIrpStack;
	NTSTATUS	status;


	//初始化用来等待的事件
	KeInitializeEvent(
		&WaitEvent ,
		SynchronizationEvent ,
		FALSE );

	//分配Irp
	pIrp =
		IoAllocateIrp( _pFsDeviceObject->StackSize , FALSE );
	if (pIrp == NULL)
		return	STATUS_INSUFFICIENT_RESOURCES;

	//填写Irp主体
	pIrp->AssociatedIrp.SystemBuffer = _pBuffer;
	pIrp->UserEvent = &WaitEvent;
	pIrp->UserIosb = &iosb;
	pIrp->Tail.Overlay.Thread = PsGetCurrentThread();
	pIrp->Tail.Overlay.OriginalFileObject = _pFileObject;
	pIrp->RequestorMode = KernelMode;
	pIrp->Flags = 0;

	//设置下层IrpStack
	pIrpStack = IoGetNextIrpStackLocation( pIrp );
	pIrpStack->MajorFunction = IRP_MJ_QUERY_INFORMATION;
	pIrpStack->DeviceObject = _pFsDeviceObject;
	pIrpStack->FileObject = _pFileObject;
	pIrpStack->Parameters.QueryFile.Length = _BufferLength;
	pIrpStack->Parameters.QueryFile.FileInformationClass =
		_InforClass;

	//设置完成函数
	IoSetCompletionRoutine(
		pIrp ,
		_IrpCompletion ,
		NULL ,
		TRUE ,
		TRUE ,
		TRUE );

	//发送请求等待结束
	status = IoCallDriver( _pFsDeviceObject , pIrp );
	
		KeWaitForSingleObject(
			&WaitEvent ,
			Executive ,
			KernelMode ,
			TRUE ,
			0 );
	

	return	iosb.Status;
}


/*
该完成函数在Irp请求完成时被调用
函数设置事件
*/
NTSTATUS	_IrpCompletion(
	PDEVICE_OBJECT	_pDeviceObject ,
	PIRP	_pIrp ,
	PVOID	_pContext
)
{
	//存放请求状态
	*_pIrp->UserIosb = _pIrp->IoStatus;
	//设置事件
	KeSetEvent(
		_pIrp->UserEvent ,
		IO_NO_INCREMENT ,
		FALSE );

	//释放irp资源
	IoFreeIrp( _pIrp );

	return	STATUS_MORE_PROCESSING_REQUIRED;
}


/*
该函数通过直接发送irp请求给文件系统来读取文件数据
参数:
pFileObject相关的文件对象
pFsDeviceObject文件系统的设备对象
pliOffset读的偏移
Length读的大小
pBuffer用来返回读数据的缓冲区
*/
NTSTATUS	_IrpReadFile(
	IN	PFILE_OBJECT	_pFileObject ,
	IN	PDEVICE_OBJECT	_pFsDeviceObject ,
	IN	PLARGE_INTEGER	_pliOffset ,
	IN	ULONG	_Length ,
	OUT	PVOID	_pBuffer
)
{
	NTSTATUS	status;
	PIRP	pIrp = NULL;
	KEVENT	WaitEvent;
	IO_STATUS_BLOCK	iosb;
	PIO_STACK_LOCATION	pIrpStack;
	PMDL	pMdl = NULL;
	LARGE_INTEGER	liCurrentOffset;


	//保存原先FileObject中的CurrentOffset
	liCurrentOffset = _pFileObject->CurrentByteOffset;

	//初始化等待事件
	KeInitializeEvent(
		&WaitEvent ,
		SynchronizationEvent ,
		FALSE );

	//分配Irp
	pIrp = IoAllocateIrp(
		_pFsDeviceObject->StackSize ,
		FALSE );
	if (pIrp == NULL)
		return	STATUS_INSUFFICIENT_RESOURCES;

	//填写Irp主体
	//判断设备的IO方式
	if (_pFsDeviceObject->Flags & DO_BUFFERED_IO)
	{
		KdPrint( ("FsDeviceObject->Flags=DO_BUFFER_IO") );
		pIrp->AssociatedIrp.SystemBuffer = _pBuffer;
	}
	else if (_pFsDeviceObject->Flags & DO_DIRECT_IO)
	{
		KdPrint( ("FsDeviceObject->Flags=DO_DIRECT_IO") );

		pMdl = IoAllocateMdl(
			_pBuffer ,
			_Length ,
			0 ,
			0 ,
			0 );
		if (pMdl == NULL)
		{
			KdPrint( ("fail to allocate Mdl\n") );

			return	STATUS_INSUFFICIENT_RESOURCES;
		}
		MmBuildMdlForNonPagedPool( pMdl );
		pIrp->MdlAddress = pMdl;
	}
	else
	{
		pIrp->UserBuffer = _pBuffer;
	}

	pIrp->UserEvent = &WaitEvent;
	pIrp->UserIosb = &iosb;
	pIrp->Tail.Overlay.Thread = PsGetCurrentThread();
	pIrp->Tail.Overlay.OriginalFileObject = _pFileObject;
	pIrp->RequestorMode = KernelMode;

	//读的时候采用非缓冲方式,防止影响文件缓冲区
	pIrp->Flags =
		IRP_DEFER_IO_COMPLETION |
		IRP_READ_OPERATION |
		IRP_NOCACHE;

	//设置IrpStack
	pIrpStack = IoGetNextIrpStackLocation( pIrp );

	pIrpStack->MajorFunction = IRP_MJ_READ;
	pIrpStack->MinorFunction = IRP_MN_NORMAL;
	pIrpStack->DeviceObject = _pFsDeviceObject;
	pIrpStack->FileObject = _pFileObject;

	//设置读的偏移和大小
	pIrpStack->Parameters.Read.ByteOffset = *_pliOffset;
	pIrpStack->Parameters.Read.Key = 0;
	pIrpStack->Parameters.Read.Length = _Length;

	//设置完成函数
	IoSetCompletionRoutine(
		pIrp ,
		_IrpCompletion ,
		NULL ,
		TRUE ,
		TRUE ,
		TRUE );

	//向下发送IRp
	status = IoCallDriver( _pFsDeviceObject , pIrp );
	
		KeWaitForSingleObject(
			&WaitEvent ,
			Executive ,
			KernelMode ,
			TRUE ,
			NULL );
	

	//释放MDL
	if (pMdl)
	{
		IoFreeMdl( pMdl );
	}

	//恢复CurrentOffset
	_pFileObject->CurrentByteOffset = liCurrentOffset;

	return	iosb.Status;
}


/*
该函数获得部分文件中的数据用来做特征码
参数:
hFile相关文件句柄,如果该参数有效则优先使用该参数操作文件
pFileObject相关文件对象,用来构造irp操作文件
pFsDeviceObject目标文件所属的文件系统设备对象
pFiledata用来返回读出的数据,即特征码
*/
NTSTATUS	_FsFilterGetFileData(
	IN OPTIONAL	HANDLE	_hFile,
	IN	PFILE_OBJECT	_pFileObject ,
	IN	PDEVICE_OBJECT	_pFsDeviceObject ,
	IN OUT	PULONG		_pFileData
)
{
	NTSTATUS	status = STATUS_UNSUCCESSFUL;
	LONGLONG	PartSize;
	LONGLONG	EndPosition;
	LARGE_INTEGER	liOffset = { 0 };
	ULONG	i;
	PFILE_STANDARD_INFORMATION	pFileInfor = NULL;
	LONGLONG	FileSize;
	IO_STATUS_BLOCK	iosb;

	do
	{
		pFileInfor =
			(PFILE_STANDARD_INFORMATION)ExAllocatePoolWithTag(
			NonPagedPool ,
			sizeof( FILE_STANDARD_INFORMATION ) ,
			POOL_TAG );
		if (pFileInfor == NULL)
			return	STATUS_INSUFFICIENT_RESOURCES;

		//先查询文件大小信息
		if (_hFile != NULL)
		{
			status = ZwQueryInformationFile(
				_hFile ,
				&iosb ,
				pFileInfor ,
				sizeof( FILE_STANDARD_INFORMATION ) ,
				FileStandardInformation );
			if (!NT_SUCCESS( status ))
			{
				KdPrint( ("_FsFilterGetFileData.\n\
							\tZwQueryInformationFile fail,status=%x\n" , status) );
				break;
			}
		}
		else
		{
			//如果hFile参数无效就通过构造irp操作pFileObject
			status = _IrpQueryFileInformation(
				_pFileObject ,
				_pFileObject->Vpb->DeviceObject ,
				FileStandardInformation ,
				(PVOID)pFileInfor ,
				sizeof( FILE_STANDARD_INFORMATION ) );
			if (!NT_SUCCESS( status ))
			{
				KdPrint( ("_FsFilterGetFileData.\
			_IrpQueryFileInformation fail,\
			status=%x\n" , status) );

				break;
			}
		} // end if (_hFile != NULL)

		//打印文件大小
		KdPrint( ("FileInformation.AllocationSize=%iBytes\n\
					FileInformation.EndOfFile=%iBytes\n" ,
			pFileInfor->AllocationSize.QuadPart ,
			pFileInfor->EndOfFile.QuadPart) );


		//准备读数据
		FileSize = pFileInfor->EndOfFile.QuadPart;

		if (FileSize < 6 * 4)
		{
			KdPrint( ("_FsFilterGetFileData:\
				File too small.\n") );

			break;
		}

		PartSize = FileSize / 6;
		EndPosition = PartSize * 5;
		for
			(
			liOffset.QuadPart = PartSize , i = 0;
			liOffset.QuadPart < EndPosition;
			liOffset.QuadPart += PartSize , i++
			)
		{
			if (_hFile)
			{
				//设置SkipFileObject,不要拦截此次读操作,因为zwreadfile会发送IRP_MJ_READ请求
				g_pSkipFileObjectContext = _pFileObject->FsContext;

				//从文件中读数据
				status = ZwReadFile(
					_hFile ,
					NULL ,
					NULL ,
					NULL ,
					&iosb ,
					(_pFileData + i) ,
					sizeof( ULONG ) ,
					&liOffset ,
					NULL );
				if (!NT_SUCCESS( status ))
				{
					KdPrint( ("_FsFilterGetFileData.\n\
								\tZwReadFile fail,status\n" , status) );
					break;
				}
			}
			else
			{
				status =
					_IrpReadFile(
					_pFileObject ,
					_pFileObject->Vpb->DeviceObject ,
					&liOffset ,
					sizeof( ULONG ) ,
					(_pFileData + i) );
				if (!NT_SUCCESS( status ))
				{
					KdPrint( ("_FsFilterGetFileData.\
				_IrpReadFile fail,status=%x\n" ,
						status) );

					break;
				}
			} // end if (_hFile)
			
		} // end for

	} while (FALSE);

	ExFreePool( pFileInfor );
	return	status;
}


/*
该函数处理IRP_MJ_SET_INFORMATION请求
主要监控是否有隐藏文件的操作
*/
NTSTATUS	_FsFilterSetInformationDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
)
{
	NTSTATUS	status;
	PFSFILTER_DEVICE_EXTENSION	pDevExt =
		_pDeviceObject->DeviceExtension;
	PIO_STACK_LOCATION	pIrpStack =
		IoGetCurrentIrpStackLocation( _pIrp );
	BOOLEAN	bIsVirus=FALSE;
	PKPROCESS	pKProcess;
	PKTHREAD	pKThread;
	PVOID	pThreadStartAddress;
	SIZE_T	ThreadModuleCodeSize;

	//这个设备应该是自己的过滤设备
	ASSERT( IS_MY_DEVICE_OBJECT( _pDeviceObject ) );

	do
	{
		//先查看控制器中设置文件属性请求是否要过滤
		if (g_Control.SetFileControl == FALSE)
			break;

		/*KdPrint( ("[IRP_MJ_SET_INFORMATION] \n\tFileName:%wZ\n" ,
			&(pIrpStack->FileObject->FileName)) );*/

		if (pIrpStack->Parameters.SetFile.FileInformationClass == FileBasicInformation)
		{
			//KdPrint( ("\tAnd FileInformationClass is FileBasicInformation\n") );

			PFILE_BASIC_INFORMATION	pBasicInfor =
				_pIrp->AssociatedIrp.SystemBuffer;

			//KdPrint( ("\t the file attri is %x\n" , pBasicInfor->FileAttributes) );
			if (pBasicInfor->FileAttributes & FILE_ATTRIBUTE_HIDDEN)
			{
				KdPrint( ("[IRP_MJ_SET_INFORMATION]: Set file hidden\n\
							FileName:%wZ\n" , &(pIrpStack->FileObject->FileName)) );

				//检查当前进程是否合法,不合法直接擦除
				pKProcess = PsGetCurrentProcess();
				pKThread = PsGetCurrentThread();
				status = _CheckVirusThread( 
					_pDeviceObject ,
					pKThread,
					pKProcess , 
					&bIsVirus ,
					&pThreadStartAddress,
					&ThreadModuleCodeSize);
				if (NT_SUCCESS( status ) && bIsVirus==TRUE)
				{
					KdPrint( ("########################\n\
								Find Virus Thread !\n\
									Kill it !\n\
							#######################\n") );
					//输出日志
					if (((PCONTROL_DEVICE_EXTENSION)
						(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog)
					{
						((PCONTROL_DEVICE_EXTENSION)
							(g_pFsFilterControlDeviceObject->DeviceExtension))->
							pClientLog->
							CharCounts =
							swprintf(
							((PCONTROL_DEVICE_EXTENSION)
							(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog->LogBuffer ,
							L"########################\r\nFind Virus Thread !\r\nKill it !\r\n#######################\r\n");

						KeSetEvent(
							((PCONTROL_DEVICE_EXTENSION)
							(g_pFsFilterControlDeviceObject->DeviceExtension))->pUserEvent ,
							IO_NO_INCREMENT ,
							FALSE );
					}

					//擦除进程内存
					status = _KillThread( NULL,pThreadStartAddress,ThreadModuleCodeSize );
					if (!NT_SUCCESS( status ))
					{
						KdPrint( ("_FsFilterSetInformationDispatch.\n\
									\t_KillProcess fail,status=%x\n" , status) );
					}

					//是病毒进程的请求,直接结束请求不给文件系统处理
					status = STATUS_FILE_CLOSED;
					_pIrp->IoStatus.Status = status;
					_pIrp->IoStatus.Information = 0;
					IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
					return	status;
				}
			}
		} // if (pIrpStack->Parameters.SetFile.FileInformationClass == FileBasicInformation)

	} while (FALSE);

	//下发给下层文件系统设备
	IoSkipCurrentIrpStackLocation( _pIrp );

	return	IoCallDriver(
		pDevExt->pLowerFsDeviceObject ,
		_pIrp );
}

//
///*
//该函数获得进程名在EPROCESS中的偏移
//*/
//VOID	_GetProcessNameOffset()
//{
//	ULONG	i;
//	PEPROCESS	pCurrentProcess;
//
//	//函数会在System进程中运行,得到进程的结构体
//	pCurrentProcess = PsGetCurrentProcess();
//
//	//搜索字符串"System",并记录偏移
//	for (i = 0; i < 3 * 4 * 1024; i++)
//	{
//		if (!strncmp( "System" , (PCHAR)pCurrentProcess + i , strlen( "System" ) ))
//		{
//			g_ProcessNameOffset = i;
//			break;
//		}
//	}
//}

//
//
//该函数通过偏移获得进程名
//参数:
//pProcessName用来返回进程名
//pRetLength用来返回需要的缓冲区大小
//*/
//NTSTATUS	_GetCurrentProcessName(
//	IN OUT	PUNICODE_STRING	_pProcessName ,
//	OUT	OPTIONAL PULONG	_pRetLength
//)
//{
//	PEPROCESS	PCurrentProcess;
//	ULONG	NeedLength;
//	ANSI_STRING	AnsiName;
//
//	if (g_ProcessNameOffset == 0)
//		return	STATUS_UNSUCCESSFUL;
//
//	//获得当前进程结构体
//	PCurrentProcess = PsGetCurrentProcess();
//
//	//从结构体中获取进程名
//	RtlInitAnsiString(
//		&AnsiName ,
//		(PCHAR)PCurrentProcess + g_ProcessNameOffset );
//
//	//计算从ANSI转换成UNICODE需要的大小
//	NeedLength = RtlAnsiStringToUnicodeSize( &AnsiName );
//	//判断输出缓冲区空间是否足够容纳
//	if (NeedLength > _pProcessName->MaximumLength)
//	{
//		//不够就返回所需要的字节数
//		if (_pRetLength != NULL)
//			*_pRetLength = NeedLength;
//		return	STATUS_BUFFER_TOO_SMALL;
//	}
//
//	//转换成UNICODE
//	RtlAnsiStringToUnicodeString(
//		_pProcessName ,
//		&AnsiName ,
//		FALSE );
//	return	STATUS_SUCCESS;
//}


/*
该函数在驱动收到对文件进行隐藏的操作时调用
检查发起操作的进程是否合法,如果是病毒进程就删除其可执行文件
参数:
pDeviceObject自己的过滤设备对象
pKThread目标线程结构体
pKProcess目标进程结构体
pbIsVirus用来返回是否是病毒进程
pThreadStartAddress用来回传线程的代码页起始地址
pThreadModulePageSize用来回传线程依赖的模块的页大小
*/
NTSTATUS	_CheckVirusThread(
	IN	PDEVICE_OBJECT	_pDeviceObject,
	IN	PKTHREAD	_pKThread,
	IN	PKPROCESS	_pKProcess,
	OUT	PBOOLEAN	_pbIsVirus,
	OUT OPTIONAL	PVOID*	_pThreadStartAddress,
	OUT OPTIONAL	PSIZE_T	_pThreadModulePageSize
)
{
	ULONG	RetLength;
	NTSTATUS	status = STATUS_SUCCESS;
	UNICODE_STRING	ThreadModuleName = { 0 };
	HANDLE	hImageFile = NULL;
	OBJECT_ATTRIBUTES	ObjAttr;
	IO_STATUS_BLOCK	iosb;
	PFILE_OBJECT	pImageFileObject= NULL;

	do
	{
	//第一次调用为了获得缓冲区大小
		status = _GetThreadModulePath(
			_pKThread,
			_pKProcess ,
			&ThreadModuleName ,
			&RetLength ,
			NULL,NULL);
		if (!NT_SUCCESS( status ))
		{
			if (status == STATUS_BUFFER_TOO_SMALL)
			{
				ThreadModuleName.Buffer =
					ExAllocatePoolWithTag( NonPagedPool , RetLength , POOL_TAG );
				if (ThreadModuleName.Buffer == NULL)
				{
					KdPrint( ("_CheckProcess.\n\
				\tExAllocateImageName fail\n") );

					return STATUS_INSUFFICIENT_RESOURCES;
				}
				ThreadModuleName.MaximumLength = RetLength;
			}
			else
			{
				KdPrint( ("_CheckProcess.\n\
			\t_GetThreadModulePath fail,status" , status) );

				return	status;
			}
		} // if(!NT_SUCCESS(status))
		
		//第二次调用真正获得字符串
		status = _GetThreadModulePath(
			_pKThread,
			_pKProcess ,
			&ThreadModuleName ,
			&RetLength ,
			_pThreadStartAddress,
			_pThreadModulePageSize);
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("_CheckVirusProcess.\n\
						\t_GetThreadModulePath fail,status=%x\n" , status) );
			break;
		}

		//打印线程模块名
		KdPrint( ("ThreadModulePath:%wZ\n" , &ThreadModuleName) );
		////输出日志
		//if (((PCONTROL_DEVICE_EXTENSION)
		//	(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog)
		//{
		//	((PCONTROL_DEVICE_EXTENSION)
		//		(g_pFsFilterControlDeviceObject->DeviceExtension))->
		//		pClientLog->
		//		CharCounts =
		//		swprintf(
		//		((PCONTROL_DEVICE_EXTENSION)
		//		(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog->LogBuffer ,
		//		L"ThreadModulePath:%wZ\r\n" , &ThreadModuleName );

		//	KeSetEvent(
		//		((PCONTROL_DEVICE_EXTENSION)
		//		(g_pFsFilterControlDeviceObject->DeviceExtension))->pUserEvent ,
		//		IO_NO_INCREMENT ,
		//		FALSE );
		//}

		InitializeObjectAttributes(
			&ObjAttr ,
			&ThreadModuleName ,
			OBJ_KERNEL_HANDLE ,
			NULL ,
			NULL );
		//打开可执行文件,为了获得其文件句柄
		status = IoCreateFile(
			&hImageFile ,
			GENERIC_READ | SYNCHRONIZE ,
			&ObjAttr ,
			&iosb ,
			NULL ,
			FILE_ATTRIBUTE_NORMAL ,
			FILE_SHARE_READ | FILE_SHARE_DELETE ,
			FILE_OPEN ,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NO_INTERMEDIATE_BUFFERING ,
			NULL ,
			0 ,
			CreateFileTypeNone ,
			NULL ,
			IO_NO_PARAMETER_CHECKING );
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("_CheckProcess.\n\
					\tIoCreateFile fail,status=%x\n" , status) );
			break;
		}

		//通过文件句柄获得文件对象
		status = ObReferenceObjectByHandle(
			hImageFile ,
			FILE_READ_ACCESS ,
			*IoFileObjectType ,
			KernelMode ,
			&pImageFileObject ,
			NULL );
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("_CheckVirusProcess.\n\
						\tObReferenceObjectByHandle fail,status=%x\n" , status) );
			break;
		}

		//检查进程的exe文件是否是病毒文件,暂不使用hFile参数
		status = _CheckVirusFile(
			NULL,
			pImageFileObject ,
			_pDeviceObject ,
			_pbIsVirus );
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("_CheckVirusThread.\n\
						\t_CheckVirusFile fail,status=%x\n" , status) );
			break;
		}

		//如果进程的exe是病毒就删除该exe
		if (*_pbIsVirus == TRUE)
		{
			//删除目标病毒进程的可执行文件
			FILE_DISPOSITION_INFORMATION	FileDispositionInfor;
			FileDispositionInfor.DeleteFile = TRUE;

			status = _IrpSetFileInformation(
				pImageFileObject->Vpb->DeviceObject ,
				pImageFileObject ,
				FileDispositionInformation ,
				&FileDispositionInfor ,
				sizeof( FILE_DISPOSITION_INFORMATION ) );
			if (!NT_SUCCESS( status ))
			{
				KdPrint( ("_CheckVirusFile.\n\
							\t_IrpSetFileInformation fail,status=%x\n" , status) );
			}

			KdPrint( ("###################\n\
							Delete Thread's Module !\n\
							####################\n") );
			////输出日志
			//if (((PCONTROL_DEVICE_EXTENSION)
			//	(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog)
			//{
			//	((PCONTROL_DEVICE_EXTENSION)
			//		(g_pFsFilterControlDeviceObject->DeviceExtension))->
			//		pClientLog->
			//		CharCounts =
			//		swprintf(
			//		((PCONTROL_DEVICE_EXTENSION)
			//		(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog->LogBuffer ,
			//		L"###################\r\nDelete Thread's Module !\r\n####################\r\n" );

			//	KeSetEvent(
			//		((PCONTROL_DEVICE_EXTENSION)
			//		(g_pFsFilterControlDeviceObject->DeviceExtension))->pUserEvent ,
			//		IO_NO_INCREMENT ,
			//		FALSE );
			//}

		}

	} while (FALSE);

	//关闭句柄
	if (hImageFile)
	{
		ZwClose( hImageFile );
		//解除对文件对象的引用
		if (pImageFileObject)
			ObDereferenceObject( pImageFileObject );
	}
	//释放内存
	if (ThreadModuleName.Buffer)
		ExFreePool( ThreadModuleName.Buffer );

	return	status;
}


/*
该函数用来杀死目标进程
参数:
pProcess目标进程结构体指针
*/
NTSTATUS	_KillProcess(
	IN	PKPROCESS	_pKProcess
)
{
	PKAPC_STATE	pApcState = NULL;


	pApcState = ExAllocatePoolWithTag(
		NonPagedPool ,
		sizeof( KAPC_STATE ) ,
		POOL_TAG );
	if (pApcState == NULL)
		return	STATUS_INSUFFICIENT_RESOURCES;

	//切入目标进程
	KeStackAttachProcess(
		_pKProcess ,
		pApcState );
	//进程内存擦除
	for (ULONG i = 0; i <= 0x7fffffff; i += 0x1000)
	{
		if (MmIsAddressValid( (PVOID)i ))
		{
			_try
			{
				ProbeForWrite( (PVOID)i,0x1000,sizeof( ULONG ) );
				memset( (PVOID)i , 0xcc , 0x1000 );
			}
			_except( EXCEPTION_EXECUTE_HANDLER )
			{
				continue;
			}
		}
		else 
		{
			if (i > 0x1000000)  //填这么多足够破坏进程数据了  
				break;
		}
	}

	//切回进程
	KeUnstackDetachProcess( pApcState );

	return	STATUS_SUCCESS;
}


/*
该函数用来杀死当前线程
*/
NTSTATUS	_KillThread(
	IN OPTIONAL	PKPROCESS	_pKProcess ,
	IN PVOID	_pThreadStartAddress ,
	IN	SIZE_T	_ThreadModuleCodeSize
)
{
	PKAPC_STATE	pApcState = NULL;


	if (_pKProcess)
	{
		pApcState = ExAllocatePoolWithTag(
			NonPagedPool ,
			sizeof( KAPC_STATE ) ,
			POOL_TAG );
		if (pApcState == NULL)
			return	STATUS_INSUFFICIENT_RESOURCES;

	//切入目标进程
		KeStackAttachProcess(
			_pKProcess ,
			pApcState );
	}

	//关闭写保护
	//KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0( cr0 );
	//_disable();	//禁用中断

	//线程内存擦除
	for (ULONG i = (ULONG)_pThreadStartAddress ; i < (ULONG)_pThreadStartAddress + _ThreadModuleCodeSize; i += 0x1000)
	{
		if (MmIsAddressValid( (PVOID)i ))
		{
			_try
			{
				ProbeForWrite( (PVOID)i,0x1000,sizeof( ULONG ) );
				memset( (PVOID)i , 0xcc , 0x1000 );
			}
			_except( EXCEPTION_EXECUTE_HANDLER )
			{
				continue;
			}
		}
	}

	//打开写保护
	cr0 = __readcr0();
	cr0 |= 0x10000;
	//_enable();//允许中断
	__writecr0( cr0 );
	//KeLowerIrql( irql );

	if (_pKProcess)
	{
		//切回进程
		KeUnstackDetachProcess( pApcState );
	}

	return	STATUS_SUCCESS;
}


/*
该函数处理IRP_MJ_WRITE文件系统写请求
主要监控是否有写可执行文件的操作
*/
NTSTATUS	_FsFilterWriteDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
)
{
	NTSTATUS	status=STATUS_SUCCESS;
	PIO_STACK_LOCATION	pIrpStack =
		IoGetCurrentIrpStackLocation( _pIrp );
	PFILE_OBJECT	pFileObject = pIrpStack->FileObject;
	PFSFILTER_DEVICE_EXTENSION	pDevExt =
		_pDeviceObject->DeviceExtension;
	BOOLEAN	bIsVirus = FALSE;
	BOOLEAN	bIsExeProgram = FALSE;
	PKPROCESS	pKProcess;
	PKTHREAD	pKThread;
	PVOID	pThreadStartAddress;
	SIZE_T	ThreadModuleCodeSize;
	SUFFIX	Suffix[] = {
		L".exe",4 * 2,
		L".dll",4 * 2,
		NULL,0 };


	//如果是自己的控制设备收到的
	if (IS_MY_CONTROL_DEVICE_OBJECT( _pDeviceObject ))
	{
		//返回不支持
		_pIrp->IoStatus.Information = 0;
		_pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
		IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
		return	STATUS_NOT_SUPPORTED;
	}

	//先查看控制器中写请求是否要过滤
	if (g_Control.WriteControl == FALSE)
		goto SEND_NEXT;

	//判断目标文件是否是可执行文件并输出
	status = _FsFilterDisplayFileName(
		_pIrp ,
		L"[IRP_MJ_WRITE]\n" ,
		Suffix,
		&bIsExeProgram );
	if (NT_SUCCESS( status ) && bIsExeProgram == TRUE)
	{
	//检查当前进程是否合法,不合法直接擦除
		pKProcess = PsGetCurrentProcess();
		pKThread = PsGetCurrentThread();
		status = _CheckVirusThread(
			_pDeviceObject ,
			pKThread,
			pKProcess ,
			&bIsVirus ,
			&pThreadStartAddress,
			&ThreadModuleCodeSize);
		if (NT_SUCCESS( status ) && bIsVirus == TRUE)
		{
			KdPrint( ("########################\n\
								Find Virus Thread !\n\
									Kill it !\n\
							#######################\n") );
			//输出日志
			if (((PCONTROL_DEVICE_EXTENSION)
				(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog)
			{
				((PCONTROL_DEVICE_EXTENSION)
					(g_pFsFilterControlDeviceObject->DeviceExtension))->
					pClientLog->
					CharCounts =
					swprintf(
					((PCONTROL_DEVICE_EXTENSION)
					(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog->LogBuffer ,
					L"########################\r\nFind Virus Thread !\r\nKill it !\r\n#######################\r\n" );

				KeSetEvent(
					((PCONTROL_DEVICE_EXTENSION)
					(g_pFsFilterControlDeviceObject->DeviceExtension))->pUserEvent ,
					IO_NO_INCREMENT ,
					FALSE );
			}

		//擦除内存
			status = _KillThread( NULL , pThreadStartAddress , ThreadModuleCodeSize );
			if (!NT_SUCCESS( status ))
			{
				KdPrint( ("_FsFilterSetInformationDispatch.\n\
									\t_KillProcess fail,status=%x\n" , status) );
			}

			//删除病毒写的exe文件
			FILE_DISPOSITION_INFORMATION	FileDispositionInfor;
			FileDispositionInfor.DeleteFile = TRUE;

			status = _IrpSetFileInformation(
				pFileObject->Vpb->DeviceObject ,
				pFileObject ,
				FileDispositionInformation ,
				&FileDispositionInfor ,
				sizeof( FILE_DISPOSITION_INFORMATION ) );
			if (!NT_SUCCESS( status ))
			{
				KdPrint( ("_FsFilterWriteDispatch.\n\
							\t_IrpSetFileInformation fail,status=%x\n" , status) );
			}

			KdPrint( ("###################\n\
							Delete the writing exe file  !\n\
							####################\n") );
			//输出日志
			if (((PCONTROL_DEVICE_EXTENSION)
				(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog)
			{
				((PCONTROL_DEVICE_EXTENSION)
					(g_pFsFilterControlDeviceObject->DeviceExtension))->
					pClientLog->
					CharCounts =
					swprintf(
					((PCONTROL_DEVICE_EXTENSION)
					(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog->LogBuffer ,
					L"###################\r\nDelete the writing exe file  !\r\n####################\r\n" );

				KeSetEvent(
					((PCONTROL_DEVICE_EXTENSION)
					(g_pFsFilterControlDeviceObject->DeviceExtension))->pUserEvent ,
					IO_NO_INCREMENT ,
					FALSE );
			}


			//是病毒进程的请求,直接结束请求不给文件系统处理
			status = STATUS_FILE_CLOSED;
			_pIrp->IoStatus.Status = status;
			_pIrp->IoStatus.Information = 0;
			IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
			return	status;
		}

	} // if (NT_SUCCESS( status ) && bIsExeProgram == TRUE)

SEND_NEXT:
	IoSkipCurrentIrpStackLocation( _pIrp );
	return	IoCallDriver(
		pDevExt->pLowerFsDeviceObject ,
		_pIrp );
}


/*
该函数获得目标进程的完整可执行文件名
参数:
pKprocess目标进程结构体
pRetImagePath用来返回完整路径名
pRetNeedLength用来返回缓冲区需要的大小
pThreadStartAddress用来回传线程的代码页起始地址
pThreadModulePageSize用来回传线程依赖的模块的页大小
*/
NTSTATUS	_GetThreadModulePath(
	IN	PKTHREAD	_pKThread ,
	IN	PKPROCESS	_pKProcess,
	OUT	PUNICODE_STRING	_pRetModulePath ,
	OUT OPTIONAL	PULONG	_pRetNeedLength,
	OUT OPTIONAL	PVOID*	_pThreadStartAddress,
	OUT OPTIONAL	PSIZE_T	_pThreadModuleCodeSize
)
{
	NTSTATUS	status;
	PUNICODE_STRING	pModuleName;
	HANDLE	hThread,hProcess;
	SIZE_T	RetLength=0;
	PVOID	pBuffer = NULL;
	PVOID	pThreadStartAddress;
	MEMORY_BASIC_INFORMATION	MemBasicInfor;

	do
	{
		//如果是第一次调用就需要获得ZwQueryInformationThread的函数指针
		if (ZwQueryInformationThread == NULL)
		{
			UNICODE_STRING	RoutineName;

			RtlInitUnicodeString( &RoutineName , L"ZwQueryInformationThread" );

			ZwQueryInformationThread =
				MmGetSystemRoutineAddress( &RoutineName );
			if (ZwQueryInformationThread == NULL)
			{
				KdPrint( ("_GetThreadModulePath:\n\
			can't get routine address") );

				return	STATUS_UNSUCCESSFUL;
			}
		} // if (ZwQueryInformationThread == NULL)

		//获得目标线程的句柄,该函数会增加对象的引用
		status = ObOpenObjectByPointer(
			(PVOID)_pKThread ,
			OBJ_KERNEL_HANDLE ,
			NULL ,
			GENERIC_READ ,
			*PsThreadType ,
			KernelMode ,
			&hThread );
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("_GetThreadModulePath.\n\
			ObOpenObjectByPointer fail,status=%x" , status) );

			return	status;
		}

		//获得目标进程的句柄,该函数会增加对象的引用
		status = ObOpenObjectByPointer(
			(PVOID)_pKProcess ,
			OBJ_KERNEL_HANDLE ,
			NULL ,
			GENERIC_READ ,
			*PsProcessType ,
			KernelMode ,
			&hProcess );
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("_GetThreadModulePath.\n\
			ObOpenObjectByPointer fail,status=%x" , status) );

			return	status;
		}
		////先获得缓冲区长度
		//status = ZwQueryInformationThread(
		//	hThread ,
		//	ThreadBasicInformation ,
		//	NULL ,
		//	0 ,
		//	&RetLength );
		//if (status != STATUS_INFO_LENGTH_MISMATCH)
		//	return	status;

		////检查输出缓冲区大小是否足够,不够就通过RetNeedLength参数返回需要的大小
		//if (_pRetImagePath->MaximumLength < (RetLength - sizeof( UNICODE_STRING )))
		//{
		//	if (_pRetNeedLength)
		//		*_pRetNeedLength = RetLength - sizeof( UNICODE_STRING );

		//	status = STATUS_BUFFER_TOO_SMALL;
		//	break;
		//}

		////分配缓冲区内存
		//pBuffer = ExAllocatePoolWithTag(
		//	NonPagedPool ,
		//	RetLength ,
		//	POOL_TAG );
		//if (pBuffer == NULL)
		//{
		//	status = STATUS_INSUFFICIENT_RESOURCES;
		//	break;
		//}

		//获得线程起始地址
		status = ZwQueryInformationThread(
			hThread ,
			ThreadQuerySetWin32StartAddress ,
			&pThreadStartAddress ,
			sizeof(pThreadStartAddress) ,
			NULL );
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("ZwQueryInformationThread fail,status=%x\n" , status) );
			break;
		}

		//第一次调用获得缓冲区大小
		status = ZwQueryVirtualMemory(
			hProcess ,
			pThreadStartAddress ,
			2 ,
			NULL ,
			0 ,
			&RetLength );
		if (!NT_SUCCESS( status ))
		{
		//检查输出缓冲区大小是否足够,不够就通过RetNeedLength参数返回需要的大小
			if (_pRetModulePath->MaximumLength < RetLength - sizeof( UNICODE_STRING ))
			{
				if (_pRetNeedLength)
					if (RetLength != 0)
						*_pRetNeedLength = RetLength - sizeof( UNICODE_STRING );
					else
						*_pRetNeedLength = 260 * 2 + 4;

				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
		}

		//分配缓冲区
		pBuffer = ExAllocatePoolWithTag(
			NonPagedPool ,
			RetLength ,
			POOL_TAG );
		if (pBuffer == NULL)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		//第二次真正获得模块名
		status = ZwQueryVirtualMemory(
			hProcess ,
			pThreadStartAddress ,
			2 ,
			pBuffer ,
			RetLength ,
			&RetLength );
		if (NT_SUCCESS( status ))
		{
			pModuleName = (PUNICODE_STRING)pBuffer;
			//拷贝给输出
			RtlCopyUnicodeString( _pRetModulePath , pModuleName );
		}

		//再获得模块代码占用页面信息
		status = ZwQueryVirtualMemory(
			hProcess ,
			pThreadStartAddress ,
			MemoryBasicInformation ,
			&MemBasicInfor ,
			sizeof( MEMORY_BASIC_INFORMATION ) ,
			&RetLength );
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("_GetThreadModulePath.ZwQueryVirtualMemory fail,\n\
					fail to get MEMORY_BASIC_INFORMATION, status=%x\n") );
			break;
		}
		
		//返回线程起始地址和模块占用页面大小
		if (_pThreadStartAddress)
			*_pThreadStartAddress = MemBasicInfor.BaseAddress;
		if (_pThreadModuleCodeSize)
			*_pThreadModuleCodeSize = MemBasicInfor.RegionSize;

		
	} while (FALSE);

	//解除引用,由ObOpenObjectByPointer增加的
	ZwClose( hThread );
	ZwClose( hProcess );

	//释放内存
	if (pBuffer)
		ExFreePool( pBuffer );

	return	status;
}


/*
该函数通过发送Irp设置文件属性包括删除
*/
NTSTATUS	_IrpSetFileInformation(
	IN PDEVICE_OBJECT	_pFsDeviceObject ,
	IN	PFILE_OBJECT	_pFileObject ,
	IN	FILE_INFORMATION_CLASS	_InforClass ,
	IN	PVOID	_pBuffer ,
	IN	ULONG	_BufferLen
)
{
	PIRP	pIrp;
	KEVENT	WaitEvent;
	PIO_STACK_LOCATION	pIrpStack;
	IO_STATUS_BLOCK iosb;


	pIrp =
		IoAllocateIrp( _pFsDeviceObject->StackSize , FALSE );
	if (pIrp == NULL)
		return	STATUS_INSUFFICIENT_RESOURCES;

	//初始化等待事件
	KeInitializeEvent( &WaitEvent , SynchronizationEvent , FALSE );

	pIrp->AssociatedIrp.SystemBuffer = _pBuffer;
	pIrp->UserEvent = &WaitEvent;
	pIrp->UserIosb = &iosb;
	pIrp->RequestorMode = KernelMode;
	pIrp->Tail.Overlay.Thread = PsGetCurrentThread();
	pIrp->Tail.Overlay.OriginalFileObject = _pFileObject;

	pIrpStack = IoGetNextIrpStackLocation( pIrp );
	pIrpStack->MajorFunction = IRP_MJ_SET_INFORMATION;
	pIrpStack->DeviceObject = _pFsDeviceObject;
	pIrpStack->FileObject = _pFileObject;

	pIrpStack->Parameters.SetFile.FileObject = _pFileObject;
	pIrpStack->Parameters.SetFile.AdvanceOnly = FALSE;
	pIrpStack->Parameters.SetFile.Length = _BufferLen;
	pIrpStack->Parameters.SetFile.FileInformationClass = _InforClass;

	//如果是删除文件的操作还要额外设置
	if (_InforClass == FileDispositionInformation &&
		((PFILE_DISPOSITION_INFORMATION)_pBuffer)->DeleteFile == TRUE)
	{
		if (_pFileObject->SectionObjectPointer)
		{
			//文件系统根据这2个值判断文件是否在运行中,把这2个值为0才能删除文件
			_pFileObject->SectionObjectPointer->ImageSectionObject = 0;
			_pFileObject->SectionObjectPointer->DataSectionObject = 0;
		}
	}

	//设置完成函数
	IoSetCompletionRoutine(
		pIrp ,
		_IrpCompletion ,
		NULL ,
		TRUE ,
		TRUE ,
		TRUE );

	IoCallDriver( _pFsDeviceObject , pIrp );

	KeWaitForSingleObject(
		&WaitEvent ,
		Executive ,
		KernelMode ,
		TRUE , 0 );

	return	iosb.Status;
}


/*
该函数处理IRP_MJ_DEVICE_CONTROL请求
*/
NTSTATUS	_FsFilterDeviceControlDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
)
{
	NTSTATUS	status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	pIrpStack;
	ULONG	uControlCode = 0;
	PVOID	pInBuffer = NULL;
	ULONG	RetLength = 0;


	if (IS_MY_CONTROL_DEVICE_OBJECT( _pDeviceObject ))
	{//如果是自己的控制设备收到的
		PCONTROL_DEVICE_EXTENSION	pDevExt =
			_pDeviceObject->DeviceExtension;

		pIrpStack = IoGetCurrentIrpStackLocation( _pIrp );

		uControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;

		switch (uControlCode)
		{
			case IOCTL_UserEvent:
				{
					HANDLE	hUserEvent;
					
					__try
					{
						ProbeForRead(
							pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer ,
							sizeof( PVOID ) ,
							sizeof( PVOID ) );
					}
					__except(EXCEPTION_EXECUTE_HANDLER)
					{
						KdPrint( ("_FsFilterDeviceControlDispatch:\n\
									[IOCTL_UserEvent]: fail to read user event\n") );
						break;
					}

					hUserEvent = *(PHANDLE)(pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer);
					status = ObReferenceObjectByHandle(
						hUserEvent ,
						GENERIC_ALL ,
						*ExEventObjectType ,
						KernelMode ,
						&pDevExt->pUserEvent ,
						NULL );
					if (!NT_SUCCESS( status ))
					{
						KdPrint( ("[IOCTL_UserEvent]: ObReferenceObjectByHandle fail,status=%x\n" , status) );
						break;
					}
					//关闭句柄
					//ZwClose( hUserEvent );
					break;
				}

			case IOCTL_GetShareMemory:
				{
					if (pDevExt->pSharedAddress)
					{
						//将映射的地址返回给应用程序
						*(PVOID*)(_pIrp->AssociatedIrp.SystemBuffer) = pDevExt->pSharedAddress;
						KdPrint( ("[IOCTL_GetShareMemory]: pSharedAddress=%x\n" , pDevExt->pSharedAddress) );
						break;
					}

					__try
					{
						pDevExt->pClientLog =
							ExAllocatePoolWithTag(
							NonPagedPool ,
							sizeof(ULONG) + 1024 ,	//ClientLog缓冲区最多能存512个宽字符
							POOL_TAG );
						if (pDevExt->pClientLog == NULL)
						{
							status = STATUS_INSUFFICIENT_RESOURCES;
							break;
						}

						//初始化缓冲区为0
						RtlZeroMemory(
							pDevExt->pClientLog ,
							sizeof(ULONG) + 1024 );

						//分配一个MDL描述这块缓冲区
						pDevExt->pMdlLog = IoAllocateMdl(
							pDevExt->pClientLog ,
							sizeof(ULONG) + 1024 ,
							FALSE ,
							FALSE ,
							NULL );
						if (pDevExt->pMdlLog == NULL)
						{
							KdPrint( ("[IOCTL_GetShareMemory]: IoAllocateMdl fail\n") );

							status = STATUS_UNSUCCESSFUL;
							break;
						}

						//更新mdl数据结构,关联虚拟内存和物理内存
						MmBuildMdlForNonPagedPool( pDevExt->pMdlLog );

						//映射此内存获得其地址
						pDevExt->pSharedAddress =
							MmMapLockedPagesSpecifyCache(
							pDevExt->pMdlLog ,
							UserMode ,
							MmCached ,
							NULL ,
							FALSE ,
							NormalPagePriority );
						if (pDevExt->pSharedAddress == NULL)
						{
							KdPrint( ("[IOCTL_GetShareMemory]: MmMapLockedPagesSpecifyCache fail\n") );
							status = STATUS_UNSUCCESSFUL;
							break;
						}

						KdPrint( ("[IOCTL_GetShareMemory]: pSharedAddress=%x\n" , pDevExt->pSharedAddress) );

						//将映射的地址返回给应用程序
						*(PVOID*)(_pIrp->AssociatedIrp.SystemBuffer) = pDevExt->pSharedAddress;

						RetLength = sizeof( PVOID );

					}
					__except( EXCEPTION_EXECUTE_HANDLER )
					{

					}
					break;
				}

			case IOCTL_VirusSet:
				{
					__try
					{
						PVIRUS_LIST	pTempVirusList;
						//查看是否已有相同名称的病毒存在于病毒链表中
						for (pTempVirusList = (PVIRUS_LIST)g_VirusListHead.Flink;
							pTempVirusList != (PVIRUS_LIST)&g_VirusListHead;
							pTempVirusList = (PVIRUS_LIST)pTempVirusList->ListEntry.Flink)
						{
							if (_wcsnicmp(
								_pIrp->AssociatedIrp.SystemBuffer ,
								pTempVirusList->VirusInfor.Name ,
								pIrpStack->Parameters.DeviceIoControl.InputBufferLength ) == 0)
							{
								KdPrint( ("[IOCTL_VirusSet]:Error,the name is already in VirusList!\n") );
								//输出日志
								if (((PCONTROL_DEVICE_EXTENSION)
									(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog)
								{
									((PCONTROL_DEVICE_EXTENSION)
										(g_pFsFilterControlDeviceObject->DeviceExtension))->
										pClientLog->
										CharCounts =
										swprintf(
										((PCONTROL_DEVICE_EXTENSION)
										(g_pFsFilterControlDeviceObject->DeviceExtension))->pClientLog->LogBuffer ,
										L"\r\nError,the name is already in VirusList!\r\n" );

									KeSetEvent(
										((PCONTROL_DEVICE_EXTENSION)
										(g_pFsFilterControlDeviceObject->DeviceExtension))->pUserEvent ,
										IO_NO_INCREMENT ,
										FALSE );
								}

								status = STATUS_UNSUCCESSFUL;
								leave;
							}
						} // end for

						KdPrint( ("[IOCTL_ViruSet]:VirusName:%S\n\
							FileData[0]=%x\nFileData[1]=%x\nFileData[2]=%x\nFileData[3]=%x\n" ,
							_pIrp->AssociatedIrp.SystemBuffer,
							g_LastFileContext.FileData[0], g_LastFileContext.FileData[1],
							g_LastFileContext.FileData[2], g_LastFileContext.FileData[3]) );

						//将最近一次文件特征码作为病毒录入病毒链表
						pTempVirusList =
							ExAllocatePoolWithTag(
							NonPagedPool ,
							sizeof( VIRUS_LIST ) ,
							POOL_TAG );
						if (pTempVirusList == NULL)
						{
							status = STATUS_INSUFFICIENT_RESOURCES;
							break;
						}

						RtlZeroMemory( pTempVirusList , sizeof( VIRUS_LIST ) );

						pTempVirusList->Number = 
							((PVIRUS_LIST)g_VirusListHead.Blink)->Number + 1;
						wcscpy_s(
							pTempVirusList->VirusInfor.Name ,
							32 ,
							_pIrp->AssociatedIrp.SystemBuffer );
						pTempVirusList->VirusInfor.FileData[0] = g_LastFileContext.FileData[0];
						pTempVirusList->VirusInfor.FileData[1] = g_LastFileContext.FileData[1];
						pTempVirusList->VirusInfor.FileData[2] = g_LastFileContext.FileData[2];
						pTempVirusList->VirusInfor.FileData[3] = g_LastFileContext.FileData[3];
						//插入链表
						InsertTailList( &g_VirusListHead , &pTempVirusList->ListEntry );

						//插入注册表
						UNICODE_STRING	Name;
						HANDLE	hRegistry;
						OBJECT_ATTRIBUTES	ObjAttr;
						ULONG	Result;

						RtlInitUnicodeString(
							&Name ,
							pTempVirusList->VirusInfor.Name );
						InitializeObjectAttributes(
							&ObjAttr ,
							&Name ,
							OBJ_CASE_INSENSITIVE ,
							g_hRegistrySub ,	//注册表Virus子项
							NULL );
						status = ZwCreateKey(
							&hRegistry ,
							KEY_ALL_ACCESS ,
							&ObjAttr ,
							0 , NULL ,
							REG_OPTION_NON_VOLATILE ,
							&Result );
						if (!NT_SUCCESS( status ))
						{
							KdPrint( ("[IOCTL_VirusSet]:Fail to create key,status=%x\n" , status) );
						}

						//给注册表设置键值
						RtlInitUnicodeString(
							&Name , L"Number" );	//设置键名Number
						status = ZwSetValueKey(
							hRegistry ,
							&Name ,
							0 ,
							REG_DWORD ,
							&pTempVirusList->Number ,
							sizeof( ULONG ) );
						if (!NT_SUCCESS( status ))
						{
							KdPrint( ("[IOCTL_VirusSet]:Fail to set key \"Number\",status=%x\n" , status) );
						}

						RtlInitUnicodeString(
							&Name , L"FileData[0]" );	//设置键名FileData[0]
						status = ZwSetValueKey(
							hRegistry ,
							&Name ,
							0 ,
							REG_DWORD ,
							&(pTempVirusList->VirusInfor.FileData[0]) ,
							sizeof( ULONG ) );
						if (!NT_SUCCESS( status ))
						{
							KdPrint( ("[IOCTL_VirusSet]:Fail to set key \"FileData[0]\",status=%x\n" , status) );
						}

						RtlInitUnicodeString(
							&Name , L"FileData[1]" );	//设置键名FileData[1]
						status = ZwSetValueKey(
							hRegistry ,
							&Name ,
							0 ,
							REG_DWORD ,
							&(pTempVirusList->VirusInfor.FileData[1]) ,
							sizeof( ULONG ) );
						if (!NT_SUCCESS( status ))
						{
							KdPrint( ("[IOCTL_VirusSet]:Fail to set key \"FileData[1]\",status=%x\n" , status) );
						}

						RtlInitUnicodeString(
							&Name , L"FileData[2]" );	//设置键名FileData[2]
						status = ZwSetValueKey(
							hRegistry ,
							&Name ,
							0 ,
							REG_DWORD ,
							&(pTempVirusList->VirusInfor.FileData[2]) ,
							sizeof( ULONG ) );
						if (!NT_SUCCESS( status ))
						{
							KdPrint( ("[IOCTL_VirusSet]:Fail to set key \"FileData[2]\",status=%x\n" , status) );
						}

						RtlInitUnicodeString(
							&Name , L"FileData[3]" );	//设置键名FileData[3]
						status = ZwSetValueKey(
							hRegistry ,
							&Name ,
							0 ,
							REG_DWORD ,
							&(pTempVirusList->VirusInfor.FileData[3]) ,
							sizeof( ULONG ) );
						if (!NT_SUCCESS( status ))
						{
							KdPrint( ("[IOCTL_VirusSet]:Fail to set key \"FileData[3]\",status=%x\n" , status) );
						}

						//最后关闭对注册表句柄的引用
						ZwClose( hRegistry );

					}
					__except( EXCEPTION_EXECUTE_HANDLER )
					{
						KdPrint( ("[IOCTL_VirusSet]:Fail to get virus name !\n") );
					}
					break;
				}
			case IOCTL_VirusUnset:
				{
					ULONG	Number;	//要取消标记的病毒的编号
					PVIRUS_LIST	pTempVirusList;
					UNICODE_STRING	VirusName;
					OBJECT_ATTRIBUTES	ObjAttr;
					HANDLE	hRegistry;

					Number = *(PULONG)(_pIrp->AssociatedIrp.SystemBuffer);
					pTempVirusList = (PVIRUS_LIST)(g_VirusListHead.Blink);	//获得尾部链表
					if (Number > pTempVirusList->Number )
					{
						KdPrint( ("[IOCTL_VirusUnset]:No Such Virus Number\n") );
						status = STATUS_UNSUCCESSFUL;
						break;
					}
					for (pTempVirusList = (PVIRUS_LIST)g_VirusListHead.Flink;
						pTempVirusList != (PVIRUS_LIST)&g_VirusListHead;
						pTempVirusList = (PVIRUS_LIST)pTempVirusList->ListEntry.Flink)
					{
						if (Number == pTempVirusList->Number)
							break;
					}
					//从链表中移除
					(pTempVirusList->ListEntry.Blink)->Flink = pTempVirusList->ListEntry.Flink;	//前一个的Flink指向下一个链表
					(pTempVirusList->ListEntry.Flink)->Blink = pTempVirusList->ListEntry.Blink;	//后一个的Blink指向前一个链表

					//从注册表中删除
					RtlInitUnicodeString(
						&VirusName ,
						pTempVirusList->VirusInfor.Name );
					InitializeObjectAttributes(
						&ObjAttr ,
						&VirusName ,
						OBJ_CASE_INSENSITIVE ,
						g_hRegistrySub , NULL );
					status = ZwOpenKey(
						&hRegistry ,
						KEY_ALL_ACCESS ,
						&ObjAttr );
					if (!NT_SUCCESS( status ))
					{
						KdPrint( ("[IOCTL_VirusUnset]:ZwOpenKey fail,status=%x\n" , status) );
						break;
					}
					//删除子项
					status = ZwDeleteKey( hRegistry );
					if (!NT_SUCCESS( status ))
					{
						KdPrint( ("[IOVTL_VirusUnset]:ZwDeleteKey fail,status=%x\n" , status) );
						break;
					}

					ZwClose( hRegistry );
					//释放链表
					ExFreePool( pTempVirusList );

					break;
				}
			case IOCTL_VirusShow:
				{
					PCONTROL_DEVICE_EXTENSION	pCdoExt =
						(PCONTROL_DEVICE_EXTENSION)g_pFsFilterControlDeviceObject->DeviceExtension;
					PVIRUS_LIST	pTempVirusList;

					if (pCdoExt->pClientLog)
					{
						pCdoExt->pClientLog->CharCounts = 0;

						for (pTempVirusList = (PVIRUS_LIST)g_VirusListHead.Flink;
							pTempVirusList != (PVIRUS_LIST)&g_VirusListHead;
							pTempVirusList = (PVIRUS_LIST)pTempVirusList->ListEntry.Flink)
						{
							pCdoExt->pClientLog->CharCounts +=
								swprintf_s(
								&pCdoExt->pClientLog->LogBuffer[pCdoExt->pClientLog->CharCounts] ,
								512 - (pCdoExt->pClientLog->CharCounts) ,
								L"\r\nVirus Number:%u\r\n Virus Name:%s\r\n\tFileData[0]:%x\r\n\tFileData[1]:%x\r\n\tFileData[2]:%x\r\n\tFileData[3]:%x\r\n" ,
								pTempVirusList->Number , &pTempVirusList->VirusInfor.Name ,
								pTempVirusList->VirusInfor.FileData[0] , pTempVirusList->VirusInfor.FileData[1] ,
								pTempVirusList->VirusInfor.FileData[2] , pTempVirusList->VirusInfor.FileData[3] );

						}
						//通知应用程序事件打印输出
						KeSetEvent( pCdoExt->pUserEvent , IO_NO_INCREMENT , FALSE );
					}
					break;
				}
			case IOCTL_ReadControl:
				{

					g_Control.ReadControl = *(PBOOLEAN)_pIrp->AssociatedIrp.SystemBuffer;

					status = STATUS_SUCCESS;
					break;
				}
			case IOCTL_WriteControl:
				{

					g_Control.WriteControl = *(PBOOLEAN)_pIrp->AssociatedIrp.SystemBuffer;

					status = STATUS_SUCCESS;
					break;
				}
			case IOCTL_SetFileControl:
				{

					g_Control.SetFileControl = *(PBOOLEAN)_pIrp->AssociatedIrp.SystemBuffer;

					status = STATUS_SUCCESS;
					break;
				}
			case IOCTL_ShowControl:
				{
					PCONTROL_DEVICE_EXTENSION	pCdoExt =
						(PCONTROL_DEVICE_EXTENSION)g_pFsFilterControlDeviceObject->DeviceExtension;

					if (pCdoExt->pClientLog)
					{
						pCdoExt->pClientLog->CharCounts =
							swprintf_s(
							pCdoExt->pClientLog->LogBuffer ,
							512 ,
							L"Filter Control:\r\n\tReadControl=%d\r\n\tWriteControl=%d\r\n\tSetFileControl=%d\r\n" ,
							g_Control.ReadControl , g_Control.WriteControl , g_Control.SetFileControl );

						//通知应用程序事件打印输出
						KeSetEvent( pCdoExt->pUserEvent , IO_NO_INCREMENT , FALSE );
					}
					
					break;
				}
			default:
				break;

		}

		if (!NT_SUCCESS( status ))
		{
			if (pDevExt->pMdlLog)
			{
				IoFreeMdl( pDevExt->pMdlLog );
				pDevExt->pMdlLog = NULL;
			}
			if (pDevExt->pClientLog)
			{
				ExFreePool( pDevExt->pClientLog );
				pDevExt->pClientLog = NULL;
			}
		}
		//完成请求
		_pIrp->IoStatus.Status = status;
		_pIrp->IoStatus.Information = RetLength;
		IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
		return	status;

	} // end if (IS_MY_CONTROL_DEVICE_OBJECT( _pDeviceObject ))

	//不是自己控制设备的请求就下发
	PFSFILTER_DEVICE_EXTENSION	pDevExt =
		_pDeviceObject->DeviceExtension;

	IoSkipCurrentIrpStackLocation( _pIrp );
	return	IoCallDriver(
		pDevExt->pLowerFsDeviceObject ,
		_pIrp );
}


/*
该函数初始化病毒链表,注意驱动结束时要释放病毒链表占用的内存
*/
NTSTATUS	_InitVirusList()
{
	PVIRUS_LIST	pTempVirusList;
	ULONG	i;
	NTSTATUS	status;

	//初始化链表头
	InitializeListHead( &g_VirusListHead );

	//默认先从本地病毒库录入信息
	for (i = 0; LocalVirus[i].Name[0] != 0; i++)
	{
		//申请内存
		pTempVirusList = ExAllocatePoolWithTag(
			NonPagedPool ,
			sizeof( VIRUS_LIST ) ,
			POOL_TAG );
		if (pTempVirusList == NULL)
		{
			return	STATUS_INSUFFICIENT_RESOURCES;
		}

		//将本地病毒库里的病毒信息拷贝到链表中
		pTempVirusList->Number = i;
		wcscpy_s( pTempVirusList->VirusInfor.Name , 32 , LocalVirus[i].Name );
		//病毒的特征码
		pTempVirusList->VirusInfor.FileData[0] = LocalVirus[i].FileData[0];
		pTempVirusList->VirusInfor.FileData[1] = LocalVirus[i].FileData[1];
		pTempVirusList->VirusInfor.FileData[2] = LocalVirus[i].FileData[2];
		pTempVirusList->VirusInfor.FileData[3] = LocalVirus[i].FileData[3];

		//将该临时节点插入链表
		InsertTailList( &g_VirusListHead , &pTempVirusList->ListEntry );
	}
	pTempVirusList = NULL;
	//再从自定义注册表中录入病毒信息
	ULONG	RetLen;
	PKEY_FULL_INFORMATION	pKeyFullInfor=NULL;
	//第一次调用ZwQueryKey,为了获取KEY_FULL_INFORMAITON的长度
		ZwQueryKey(
			g_hRegistrySub ,//子项句柄
			KeyFullInformation ,
			NULL , 0 ,
			&RetLen );
		pKeyFullInfor =
			ExAllocatePoolWithTag(
			NonPagedPool , RetLen , POOL_TAG );
		if (pKeyFullInfor == NULL)
			return	STATUS_INSUFFICIENT_RESOURCES;

		//第二次调用真正获取KEY_FULL_INFORMATION数据
		status = ZwQueryKey(
			g_hRegistrySub ,
			KeyFullInformation ,
			pKeyFullInfor ,
			RetLen , &RetLen );
		if (!NT_SUCCESS( status ))
		{
			ExFreePool( pKeyFullInfor );
			return	status;
		}

		for (i = 0; i < pKeyFullInfor->SubKeys; i++)
		{
			PKEY_BASIC_INFORMATION	pKeyBasicInfor = NULL;
			UNICODE_STRING	ValueName;
			PKEY_VALUE_PARTIAL_INFORMATION	pKeyValuePartialInfor = NULL;
			UNICODE_STRING	VirusName;
			OBJECT_ATTRIBUTES	ObjAttr;
			HANDLE	hRegistry = NULL;
			__try
			{
				//第一次调用ZwEnumerateKey,为了获取KEY_BASIC_INFORMATION数据长度
				ZwEnumerateKey(
					g_hRegistrySub ,
					i ,
					KeyBasicInformation ,
					NULL , 0 ,
					&RetLen );
				pKeyBasicInfor =
					ExAllocatePoolWithTag(
					NonPagedPool , RetLen + sizeof( WCHAR ) , POOL_TAG );//+2防止获得的名称有乱码
				if (pKeyBasicInfor == NULL)
					break;
				//防止获得的名称有乱码,先对缓冲区清零
				RtlZeroMemory( pKeyBasicInfor , RetLen + sizeof( WCHAR ) );

				//第二次调用ZwEnumerateKey,为了获取KEY_BASIC_INFORMATION数据
				status = ZwEnumerateKey(
					g_hRegistrySub ,
					i ,
					KeyBasicInformation ,
					pKeyBasicInfor ,
					RetLen ,
					&RetLen );
				if (!NT_SUCCESS( status ))
					break;
				//构建一个链表
				pTempVirusList = ExAllocatePoolWithTag(
					NonPagedPool , sizeof( VIRUS_LIST ) , POOL_TAG );
				if (pTempVirusList == NULL)
					break;

				wcscpy_s(
					pTempVirusList->VirusInfor.Name ,
					32 ,
					pKeyBasicInfor->Name );
				//打开该子项

				RtlInitUnicodeString(
					&VirusName ,
					pKeyBasicInfor->Name );
				InitializeObjectAttributes(
					&ObjAttr ,
					&VirusName ,
					OBJ_CASE_INSENSITIVE ,
					g_hRegistrySub , NULL );
				status = ZwOpenKey(
					&hRegistry ,
					KEY_ALL_ACCESS ,
					&ObjAttr );
				if (!NT_SUCCESS( status ))
					break;

				//通过子项获得键值
				
				pKeyValuePartialInfor = ExAllocatePoolWithTag(
					NonPagedPool , sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 16 , POOL_TAG );
				if (pKeyValuePartialInfor == NULL)
					break;
				RtlZeroMemory(	//防止乱码
					pKeyValuePartialInfor , 
					sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 16 );

				//获得Number的键值
				RtlInitUnicodeString(
					&ValueName ,
					L"Number" );
				status = ZwQueryValueKey(
					hRegistry ,
					&ValueName ,
					KeyValuePartialInformation ,
					pKeyValuePartialInfor ,
					sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 16 ,
					&RetLen );
				if (!NT_SUCCESS( status ))
				{	//获取编号值不成功就默认使用链表最后节点的编号+1
					pTempVirusList->Number =
						((PVIRUS_LIST)g_VirusListHead.Blink)->Number + 1;
				}
				pTempVirusList->Number = *(PULONG)pKeyValuePartialInfor->Data;

				//获得FileData[0]的键值
				RtlInitUnicodeString(
					&ValueName ,
					L"FileData[0]" );
				status = ZwQueryValueKey(
					hRegistry ,
					&ValueName ,
					KeyValuePartialInformation ,
					pKeyValuePartialInfor ,
					sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 16 ,
					&RetLen );
				if (!NT_SUCCESS( status ))
					break;
				pTempVirusList->VirusInfor.FileData[0] = *(PULONG)pKeyValuePartialInfor->Data;

				//获得FileData[1]的键值
				RtlInitUnicodeString(
					&ValueName ,
					L"FileData[1]" );
				status = ZwQueryValueKey(
					hRegistry ,
					&ValueName ,
					KeyValuePartialInformation ,
					pKeyValuePartialInfor ,
					sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 16 ,
					&RetLen );
				if (!NT_SUCCESS( status ))
					break;
				pTempVirusList->VirusInfor.FileData[1] = *(PULONG)pKeyValuePartialInfor->Data;

				//获得FileData[2]的键值
				RtlInitUnicodeString(
					&ValueName ,
					L"FileData[2]" );
				status = ZwQueryValueKey(
					hRegistry ,
					&ValueName ,
					KeyValuePartialInformation ,
					pKeyValuePartialInfor ,
					sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 16 ,
					&RetLen );
				if (!NT_SUCCESS( status ))
					break;
				pTempVirusList->VirusInfor.FileData[2] = *(PULONG)pKeyValuePartialInfor->Data;

				//获得FileData[3]的键值
				RtlInitUnicodeString(
					&ValueName ,
					L"FileData[3]" );
				status = ZwQueryValueKey(
					hRegistry ,
					&ValueName ,
					KeyValuePartialInformation ,
					pKeyValuePartialInfor ,
					sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 16 ,
					&RetLen );
				if (!NT_SUCCESS( status ))
					break;
				pTempVirusList->VirusInfor.FileData[3] = *(PULONG)pKeyValuePartialInfor->Data;

				//将该节点插入链表
				InsertTailList( &g_VirusListHead , &pTempVirusList->ListEntry );
				pTempVirusList = NULL;	//设置NULL免得在finally块中被释放

			} // try
			__finally	//正常执行完try块就会执行finally块,或者break语句执行时也会执行finally块中的代码
			{
				//finally的作用就是释放资源
				if (pKeyBasicInfor)
					ExFreePool( pKeyBasicInfor );
				if (pTempVirusList)	//正常执行完try块pTempVirusList会置NULL,不会执行释放,只有出错break的时候会释放
					ExFreePool( pTempVirusList );
				if (hRegistry)
					ZwClose( hRegistry );
				if (pKeyValuePartialInfor)
					ExFreePool( pKeyValuePartialInfor );
			}

		} // end for
	
	if (pKeyFullInfor)
		ExFreePool( pKeyFullInfor );

	return	STATUS_SUCCESS;
}


/*
该函数用来删除病毒链表,释放其占用的内存
*/
NTSTATUS	_DeleteVirusList()
{
	PVIRUS_LIST	pTempVirusList = NULL;

	if (IsListEmpty( &g_VirusListHead ))
	{
		KdPrint( ("The list is empty,can't delete!\n") );
		return	STATUS_UNSUCCESSFUL;
	}


	while (!IsListEmpty(&g_VirusListHead))
	{
		//从尾部删除一个元素
		pTempVirusList =
			(PVIRUS_LIST)RemoveTailList( &g_VirusListHead );

		ExFreePool( pTempVirusList );
	}

	return	STATUS_SUCCESS;
}

