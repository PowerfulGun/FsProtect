/*
	С�ͷ���������,sfilter�͹��˿��
						---PowerfulGun
*/

#include	"FsProtect.h"

//ȫ�ֱ���
PDEVICE_OBJECT	g_pFsFilterControlDeviceObject = NULL;	//����������ʹ�õĿ����豸
PDRIVER_OBJECT	g_pFsFilterDriverObject = NULL;	//��������������
FAST_MUTEX	g_FastMutexAttach;
FILEOBJCONTEXT	g_LastFileContext;	//��������֮ǰ���ļ�������Ϣ
PVOID	g_pSkipFileObjectContext;	//����������Ҫ���������ļ�����
LIST_ENTRY	g_VirusListHead;	//��������ͷ
HANDLE	g_hRegistrySub = NULL;	//ע�����
FILTER_CONTROL	g_Control = { TRUE ,TRUE,TRUE};	//ȫ���������˿�����

//Ĭ�ϵı��ز�����,��Щ���ݻᱻ��ӵ�ע�����,֮�󲡶�������/ɾ��������ע����н���
VIRUS	LocalVirus[] =
{
	//L"mspaint",
	//L"mspaint.exe",
	//L"mspaint.exe",
	//0x0,0xffc85d29 ,0xa5acf974 ,0x808080,	//mspaint��������

	//L"notepad",
	//L"notepad.exe",
	//L"notepad.exe",
	//0x103,0x577e,0x553b12,0xf43ddac7,	//notepad��������

	L"����481",								//����481����,�ò����ὫU���ļ�������,������ͬ��exe����ð���ļ���(ͼ����xpϵͳ�ļ��е�ͼ��)
	L"explorer.exe",						//�ò���ʹ���Լ��Ľ���explorer.exe,ð��windows��ͬ����Դ����������(Windows�Լ���explorer.exe�ϴ�)
	L"explorer.exe",						//�ò�����C:\Program Files (x86)\explorer.exe�����Լ�,��Windows������C:\Windows\explorer.exe
	0x0,0xcc58c22f,0x861ad7ed,0xe418e767,	//��������

	L"����665",								//����665����,�ò����ὫU���ļ�������,������ͬ��exe����ð���ļ���(ͼ����Win7ϵͳ�ļ��е�ͼ��)
	L"rundll32.exe",						//�ò���ʹ���Լ��Ľ���rundll32.exe,ð��windows��ͬ��rundll32.exe
	L"rundll32.exe",						//�ò�����C:\Users\Administrator\AppData\Roaming\Microsoft\Office\rundll32.exe����,��Windows������C:\Windows\System32\rundll32.exe
	0x3300444f,0xddd8dd32,0x8c24,0x3030000,	//��������

	0,0,0,0,0,0,0	//����ĩβ,������������˳�
};

/*
�������
��һ���������Լ�ʹ�õĿ����豸CDO��������Ӧ�ó���ͨ��
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


	//��ʼ�����ٻ����壬֮����豸ʱ�õ�
	ExInitializeFastMutex( &g_FastMutexAttach );

	//�����Լ�����������֮����õ�
	g_pFsFilterDriverObject = _pDriverObject;

	//��ӡ����ע���·��
	KdPrint( ("RegistryPath:%wZ\n" , _pRegistryPath) );
	//��ע�����
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
	//�رո�ע�����
	ZwClose( hRegistryRoot );

	//��ʼ����������,��������������֮��ʶ�𲡶�
	status = _InitVirusList();
	if (!NT_SUCCESS( status ))//������ɹ���û�б�Ҫִ��֮����ļ�ϵͳ�󶨲�����
		return	status;

	do
	{
		//�����Լ��Ŀ����豸��
		RtlInitUnicodeString( &DeviceName , L"\\FileSystem\\Filters\\FsProtect" );
		//���ɱ������Ŀ����豸
		status = IoCreateDevice(
			_pDriverObject ,
			sizeof(CONTROL_DEVICE_EXTENSION) ,	//�豸��չ
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
		//��ʼ���豸��չ
		RtlZeroMemory(
			g_pFsFilterControlDeviceObject->DeviceExtension ,
			sizeof( CONTROL_DEVICE_EXTENSION ) );

		g_pFsFilterControlDeviceObject->Flags |= DO_BUFFERED_IO;

		//��������������
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

		//����Ĭ�Ϸַ�����
		for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		{
			_pDriverObject->MajorFunction[i] = _FsFilterDefaultDispatch;
		}

		//��������ķַ�����
		_pDriverObject->MajorFunction[IRP_MJ_CREATE] = _FsFilterCreateDispatch;
		//_pDriverObject->MajorFunction[IRP_MJ_CREATE_NAMED_PIPE] = _FsFilterCreateDispatch;
		//_pDriverObject->MajorFunction[IRP_MJ_CREATE_MAILSLOT] = _FsFilterCreateDispatch;

		_pDriverObject->MajorFunction[IRP_MJ_READ] = _FsFilterReadDispatch;	//���ض�����

		_pDriverObject->MajorFunction[IRP_MJ_WRITE] = _FsFilterWriteDispatch;	//����д����

		_pDriverObject->MajorFunction[IRP_MJ_CLOSE] = _FsFilterCloseDispatch;

		_pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = _FsFilterDeviceControlDispatch;

		_pDriverObject->MajorFunction[IRP_MJ_FILE_SYSTEM_CONTROL] = _FsFilterControlDispatch;

		_pDriverObject->MajorFunction[IRP_MJ_SET_INFORMATION] = _FsFilterSetInformationDispatch;	//���������ļ���������

		_pDriverObject->DriverUnload = _DriverUnload;

		//���ø������Ŀ���io�ַ���
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

		//�����������п��ٺ���
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

		//�����ٷַ���ָ������������
		_pDriverObject->FastIoDispatch = pFastIoDispatch;

		//ע���ļ�ϵͳ����ص�,�����ļ�ϵͳ����ʱ�����FsChangeCallBack
		status = IoRegisterFsRegistrationChange( _pDriverObject , _FsChangeCallback );
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("FsFilter.DriverEntry.IoRegisterFsRegistrationChange fail\n status=%x\n" , status) );
			break;
		}

	} while (FALSE);

	//������
	//�ж�status�Ƿ�ɹ���ʧ��Ҫ�ͷ���Դ
	if (!NT_SUCCESS( status ))
	{
		if (g_pFsFilterControlDeviceObject)
			IoDeleteDevice( g_pFsFilterControlDeviceObject );

		if (pFastIoDispatch)
		{
			_pDriverObject->FastIoDispatch = NULL;
			ExFreePoolWithTag( pFastIoDispatch , POOL_TAG );

			//ɾ������������
			IoDeleteSymbolicLink( &Win32Name );
		}

		return	status;
	}

	return	STATUS_SUCCESS;
}

/*
_FsFilterDefaultDispatch������Ҫ����ֱ���·����²�������irp
*/
NTSTATUS	_FsFilterDefaultDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
)
{
	//�ж��Ƿ����Լ��Ŀ����豸
	if (IS_MY_CONTROL_DEVICE_OBJECT( _pDeviceObject ))
	{
		_pIrp->IoStatus.Status = STATUS_SUCCESS;
		_pIrp->IoStatus.Information = 0;
		IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
		return	STATUS_SUCCESS;
	}

	//����ֱ���·��������豸���²��豸
	IoSkipCurrentIrpStackLocation( _pIrp );
	return	IoCallDriver(
		((PFSFILTER_DEVICE_EXTENSION)_pDeviceObject->DeviceExtension)->pLowerFsDeviceObject ,
		_pIrp );
}

/*
_FsFilterAttachDeviceToDeviceStack
���𽫹����豸�󶨵��ļ�ϵͳ�豸ջ��
����:
sourceDevice:�����豸
targetDevice:Ŀ���豸
*LowerDeviceObject:���������²��豸
*/
NTSTATUS	_FsFilterAttachToDeviceStack(
	IN	PDEVICE_OBJECT	_pSourceDevice ,
	IN	PDEVICE_OBJECT	_pTargetDevice ,
	IN OUT	PDEVICE_OBJECT*	_pLowerDevice
)
{
	//���Ըú����Ƿ����ʹ�÷�ҳ�ڴ�
	PAGED_CODE();

	return	IoAttachDeviceToDeviceStackSafe(
		_pSourceDevice ,
		_pTargetDevice ,
		_pLowerDevice );

	/*
	//�Ͱ汾����
	*_pLowerDevice  = _pTargetDeivce;
	*_pLowerDevice = IoAttachDeviceToDeviceStack(_pSourceDevice,_pTargetDevice);
	if(*_pLowerDevice == NULL)
	return	STATUS_NO_SUCH_DEVICE;

	return	STATUS_SUCCESS;
	*/
}

/*
_FsChangeCallback
�����ļ�ϵͳ����ʱ����ô˺���
����:
pFsControlDeviceObject���ļ�ϵͳ�����豸ջ��ջ���豸
FsActive��ʾ�ļ�ϵͳ�ļ������ж��
*/
VOID	_FsChangeCallback(
	IN	PDEVICE_OBJECT	_pFsControlDeviceObject ,
	IN	BOOLEAN		_bFsActive
)
{
	UNICODE_STRING	DeviceName;
	WCHAR	DeviceNameBuffer[64];
	PAGED_CODE();

	//���豸����ӡ����
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
	������ļ�ϵͳ�����ô��Ҫ���ļ�ϵͳ�Ŀ����豸
	������ļ�ϵͳж�أ���Ҫ���ԭ�еİ�
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
�ú�����ö�������
����:
pObject����ָ��
pUNICODE_STRING����ָ��
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
����ĺ����������ļ�ϵͳ�Ŀ����豸
��֮���о����ʱ���֪��
������
FsControlDevice�ļ�ϵͳ�Ŀ����豸
DeviceName�豸����
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
		//����豸�����Ƿ��ǹ��ĵ��豸
		if (!IS_DESIRED_DEVICE_TYPE( _pFsControlDevice->DeviceType ))
			return	STATUS_SUCCESS;

		//׼����ø��豸��������������
		RtlInitEmptyUnicodeString(
			&DriverName ,
			DriverNameBuffer ,
			sizeof( DriverNameBuffer ) );
		_FsFilterGetObjectName( _pFsControlDevice->DriverObject , &DriverName );

		RtlInitUnicodeString( &FsRecName , L"\\FileSystem\\Fs_Rec" );
		//�鿴�����Ƿ����ļ�ϵͳʶ�������Ǿ�ֱ�ӷ���������
		if (RtlCompareUnicodeString( &DriverName , &FsRecName , TRUE ) == 0)
			return	STATUS_SUCCESS;

		//����һ���µ��豸���������豸
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

		//���ɹ����豸��Ҫ��ԭ���豸�������ֱ�ʶ��Ϊ����ϵͳ�����������豸��ԭ���豸ûʲô����
		if (FlagOn( _pFsControlDevice->Flags , DO_BUFFERED_IO ))
			SetFlag( pFilterDeviceObject->Flags , DO_BUFFERED_IO );

		if (FlagOn( _pFsControlDevice->Flags , DO_DIRECT_IO ))
			SetFlag( pFilterDeviceObject->Flags , DO_DIRECT_IO );

		if (FlagOn( _pFsControlDevice->Characteristics , FILE_DEVICE_SECURE_OPEN ))
			SetFlag( pFilterDeviceObject->Characteristics , FILE_DEVICE_SECURE_OPEN );

		//��ù����豸���豸��չָ��
		pDevExt = pFilterDeviceObject->DeviceExtension;
		//ʹ�ð󶨺��������ɵĹ����豸�󶨵��ļ�ϵͳ�����豸ջ
		status = _FsFilterAttachToDeviceStack(
			pFilterDeviceObject ,
			_pFsControlDevice ,
			&pDevExt->pLowerFsDeviceObject );
		if (!NT_SUCCESS( status ))
		{
			KdPrint( ("_FsFilterAttachToControlDevice._FsFilterAttachToDeviceStack fail,status=%x\n" , status) );
			break;
		}

		//���ļ�ϵͳ�����豸���豸���Ƽ�¼�������豸���豸��չ��
		RtlInitEmptyUnicodeString(
			&pDevExt->DeviceName ,
			pDevExt->DeviceNameBuffer ,
			sizeof( pDevExt->DeviceNameBuffer ) );
		RtlCopyUnicodeString( &pDevExt->DeviceName , _pDeviceName );
		//���ù����豸�ѳ�ʼ��
		pDevExt->DeviceTag = POOL_TAG;
		ClearFlag( pFilterDeviceObject->Flags , DO_DEVICE_INITIALIZING );

		//���Ŀ�����ϵͳ�ں˰汾����0x501������EnumerateDeviceObjectList�Ⱥ���
		//�Ϳ���ö�����о������
		status = _FsFilterEnumrateFileSystemVolumes(
			_pFsControlDevice );
		if (!NT_SUCCESS( status ))
		{
			//������ļ�ϵͳ�����豸�İ�
			IoDetachDevice( pDevExt->pLowerFsDeviceObject );
			break;
		}
	} while (FALSE);

	//������
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
�ú���ö���ļ�ϵͳ�ϵ����еľ�����
Ŀ���ļ�ϵͳ�������Ѽ�����Ҿ��ѹ��أ����Կ��Ե��ô˺���
_pFsControlDevice���ļ�ϵͳ�Ŀ����豸
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


	//�ҳ��ļ�ϵͳ�豸�����ж��٣�ͨ���������0ʵ��
	status =
		IoEnumerateDeviceObjectList(
		_pFsControlDevice->DriverObject ,
		NULL ,
		0 ,		//��������0
		&FsDeviceNum );	//������ͨ��FsDeviceNum����ʵ������
	if (!NT_SUCCESS( status ))
	{
		ASSERT( status == STATUS_BUFFER_TOO_SMALL );

		//Ϊ�豸������ڴ�
		FsDeviceNum += 8;	//���һЩ����Ĳ�
		pDeviceList =
			ExAllocatePoolWithTag(
			NonPagedPool ,
			FsDeviceNum * sizeof( PDEVICE_OBJECT ) ,
			POOL_TAG );
		if (pDeviceList == NULL)
			return	STATUS_INSUFFICIENT_RESOURCES;

		//�ٴλ���ļ�ϵͳ�豸��
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

		//�����ļ�ϵͳ�豸���е��豸�����ж��Ƿ�Ӧ�ð�
		for (i = 0; i < FsDeviceNum; i++)
		{
			pStorageStackDevice = NULL;

			try
			{
				/*
				�������������Ͳ��ð󶨣�
				���Ǹ������豸�����Ǵ���Ĳ�����
				����豸���Ͳ�ƥ��
				����豸�Ѿ����Ұ�
				*/
				if ((pDeviceList[i] == _pFsControlDevice) ||
					(pDeviceList[i]->DeviceType != _pFsControlDevice->DeviceType) ||
					_FsIsAttachedToDevice( pDeviceList[i] , NULL ))
				{
					leave;
				}

				/*
				����豸�Ƿ������ƣ������ƾ�һ���ǿ����豸���Ͳ���
				�е��ļ�ϵͳ���������ж�������豸����fastfat
				*/
				RtlInitEmptyUnicodeString(
					&DeviceName ,
					DeviceNameBuffer ,
					sizeof( DeviceNameBuffer ) );
				_FsFilterGetBaseDeviceObjectName( pDeviceList[i] , &DeviceName );
				if (DeviceName.Length > 0)
					leave;

				//�õ����豸���󣬿��豸����ͨ��vpb���ļ�ϵͳ���豸����
				//������ֻ���й������豸���ļ�ϵͳ�豸����
				//�ú����ᵼ�¿��豸��pStorageStackDevice������������
				//���û���finally���н��
				status =
					IoGetDiskDeviceObject(
					pDeviceList[i] ,
					&pStorageStackDevice );
				if (!NT_SUCCESS( status ))
					leave;

				//ͨ����õĿ��豸�����ж��Ƿ���һ����Ӱ�豸
				//���󶨾�Ӱ�豸
				status =
					_FsFilterIsShadowCopyVolume(
					pStorageStackDevice ,
					&IsShadowCopyVolume );
				if (NT_SUCCESS( status ) &&
					IsShadowCopyVolume)
				{
					//��ӡ��Ӱ�豸����
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

					//�뿪try�飬����finally�������ã�
					//Ȼ�������һ��ѭ��
					leave;
				}

				//����һ�������豸����
				status =
					IoCreateDevice(
					g_pFsFilterDriverObject ,
					sizeof( FSFILTER_DEVICE_EXTENSION ) ,
					NULL ,	//����
					pDeviceList[i]->DeviceType ,
					0 ,
					FALSE ,
					&pFilterDevice );
				if (!NT_SUCCESS( status ))
					leave;

				//���ù����豸���豸��չ�еı�ʶ�����豸
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
				�ٴ���֤�Ƿ��豸�Ѿ��󶨹�
				ʹ��һ�����ٻ����壬ȷ����ѯ��󶨵Ĳ�����ԭ�ӽ���
				*/
				ExAcquireFastMutex( &g_FastMutexAttach );

				if (!_FsIsAttachedToDevice( pDeviceList[i] , NULL ))
				{
					//��
					status = _FsFilterAttachToMountedDevice(
						pDeviceList[i] ,
						pFilterDevice );
					if (!NT_SUCCESS( status ))
					{
						/*
						�����ʧ�ܾ�ɾ���������豸
						ʧ��ԭ��֮һ���Ǿ��豸���ڹ��أ�
						DO_DEVICE_INITIALIZING ��ʶû�����
						*/
						IoDeleteDevice( pFilterDevice );
					}

				}
				else // if (!_FsIsAttachedToDevice( &pDeviceList[i] , NULL ))
				{
					//�ļ�ϵͳ�豸���ж��Ѿ�����
					//ɾ�������Ĺ����豸
					IoDeleteDevice( pFilterDevice );
				} //end if(!_FsIsAttachedToDevice( &pDeviceList[i] , NULL ))

				  //�ͷſ��ٻ�����
				ExReleaseFastMutex( &g_FastMutexAttach );
			}
			finally
			{
				/*
				�����IoGetDiskDeviceObject���ӵĶԿ��豸������
				*/
				if (pStorageStackDevice != NULL)
				{
					ObDereferenceObject( pStorageStackDevice );
				}

				/*
				�����IoEnumerateDeviceObjectList���ӵ�
				���ļ�ϵͳ�豸ջ�е��豸������
				*/
				ObDereferenceObject( pDeviceList[i] );
			}

		}	//end for (i = 0; i < FsDeviceNum; i++)

			//���԰󶨴���ֻ����STATUS_SUCCESS
		status = STATUS_SUCCESS;

		//ɾ���豸��ռ�õ��ڴ�
		ExFreePool( pDeviceList );

	}//end if(!NT_SUCCESS(STATUS))

	 //�������IoEnumerateDeviceObjectListʧ��
	 //ֱ�ӷ���ʧ�ܵ�status
	 //���򷵻صĶ����������õ�STATUS_SUCCESS
	return	status;
}


/*
��ö���ļ�ϵͳ�豸��ʱ���ô˺�������豸ջ�ײ��豸���豸��
����ײ��豸�����ͷ��ؿ��ַ���
����:
pDeviceObject �ļ�ϵͳ�豸
pDeviceName ���������豸����
*/
VOID	_FsFilterGetBaseDeviceObjectName(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN OUT	PUNICODE_STRING	_pDeviceName
)
{
	PDEVICE_OBJECT	pFsBaseDevice = NULL;

	//��õײ��豸
	pFsBaseDevice =
		IoGetDeviceAttachmentBaseRef( _pDeviceObject );

	//��õײ��豸��
	_FsFilterGetObjectName( pFsBaseDevice , _pDeviceName );

	//Ҫ����ײ��豸������,��ΪIoGetDeviceAttachmentBaseRef�����ӶԵײ��豸������
	ObDereferenceObject( pFsBaseDevice );
}


/*�ú��������豸ջ���鿴�Ƿ����Լ����ɵ��豸������о�ͨ��
AttachedDeviceObject���ظ��豸
������ǰ����豸ջ����TRUE������FALSE
*/
BOOLEAN	_FsIsAttachedToDevice(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	OUT OPTIONAL	PDEVICE_OBJECT* _ppAttachedDeviceObject
)
{
	PAGED_CODE();
	PDEVICE_OBJECT	pCurrentDevObj , pNextDevObj;


	/*
	�Ȼ�ø��豸ջ�����豸
	�õ��û����Ӷ����豸��������ü���
	*/
	pCurrentDevObj =
		IoGetAttachedDeviceReference( _pDeviceObject );

	//���϶���ɨ���豸ջ���ҳ��Լ����豸
	do
	{
		if (IS_MY_DEVICE_OBJECT( pCurrentDevObj ))
		{
			//�ҵ����Լ����豸�����Ҫ��������豸����
			//����豸������Ҫ�ں�����������
			//�����ؾ������������
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

		//����豸ջ����һ���豸���õ��û������²��豸�����ü���
		pNextDevObj =
			IoGetLowerDeviceObject( pCurrentDevObj );

		//����豸ջ����һ���豸������
		ObDereferenceObject( pCurrentDevObj );

		pCurrentDevObj = pNextDevObj;
	} while (pCurrentDevObj != NULL);

	//���û�ҵ��ͷ���FALSE
	if (ARGUMENT_PRESENT( _ppAttachedDeviceObject ))
		*_ppAttachedDeviceObject = NULL;

	return	FALSE;
}


/*
�˺������һ���ѹ��ص��ļ�ϵͳ���豸
DeviceObject���Ǳ�����豸(�ļ�ϵͳ�ľ��豸)
FilterDeviceObject���Լ��Ĺ����豸
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

	//�ڰ��豸֮ǰ����Ҫ������һЩ�����豸�ı�ʶ
	if (FlagOn( _pFsDeviceObject->Flags , DO_BUFFERED_IO ))
	{
		SetFlag( _pFilterDeviceObject->Flags , DO_BUFFERED_IO );
	}
	if (FlagOn( _pFsDeviceObject->Flags , DO_DIRECT_IO ))
	{
		SetFlag( _pFilterDeviceObject->Flags , DO_DIRECT_IO );
	}

	/*
	ѭ�����԰��豸����
	�������������Ĳ�������mount��dismount
	���п���ʧ�ܣ����Է������Աܿ��ɺ�
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

		//������ɰ�ʧ��
		//�Ͱѵ�ǰ�߳��ӳ�500ms���ټ�����
		KeDelayExecutionThread(
			KernelMode ,
			FALSE ,
			&liInterval );
	}

	return	status;
}


/*
�ú����жϸ����Ŀ��豸�Ƿ���һ����Ӱ�����豸
��Ӱ�����豸��Windows xp֮����֣���Ӱ�����豸����������������
Ϊ\Driver\VolSnap�������豸���Ϊread-only
Windows Server 2003��ͨ���鿴�豸��DeviceType��FILE_DEVICE_VIRTUAL_DISK
���ж��Ǿ�Ӱ�����豸
������
StorageStackDeviceObject�ǿ��豸����
IsShadowCopy�����Ƿ��Ǿ�Ӱ�豸
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

	//Ĭ����Ϊ����
	*_pbIsShadowCopy = FALSE;

	//��ÿ��豸����
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
	//�ж������Ƿ��ǡ�\Driver\VolSnap��
	if (RtlEqualUnicodeString(
		&pStorageDriverName->Name ,
		&VolSnapDriverName ,
		TRUE ))
	{
		*_pbIsShadowCopy = TRUE;
		return	STATUS_SUCCESS;
	}

	/*
	Windows Server 2003 ֮��İ汾
	ͨ���鿴�豸�����Ƿ���FILE_DEVICE_VIRTUAL_DISK
	���Ҿ�Ӱ�豸�Ǹ�read-only�豸
	*/
	PIRP	pIrp;
	KEVENT	WaitEvent;
	IO_STATUS_BLOCK	iosb;
	//�������豸���Ͳ���FILE_DEVICE_VIRTUAL_DISK�ǾͲ���
	if (_pStorageStackDeviceObject->DeviceType !=
		FILE_DEVICE_VIRTUAL_DISK)
		return	STATUS_SUCCESS;

	//�����FILE_DEVICE_VIRTUAL_DISK
	//�ٹ���һ����ѯ�豸�Ƿ��д��IRP��������
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
	//����ͬ��Irp
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

	//��Irp���͸��豸
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

	//����豸��д����������һ����Ӱ�����豸
	if (status == STATUS_MEDIA_WRITE_PROTECTED)
	{
		*_pbIsShadowCopy = TRUE;
		status = STATUS_SUCCESS;
	}

	return	status;
}


/*
�ú�������IRP_MJ_FILE_SYSTEM_CONTROL
�����¼�����ͬ�Ĵι��ܺ�Ҫ����
1.IRP_MN_MOUNT_VOLUME������һ�������أ��ǰ��ļ�ϵͳ���豸��ʱ��
2.IRP_MN_LOAD_FILE_SYSTEM�����֮ǰ�󶨵Ŀ����豸���ļ�ϵͳʶ������
�����ļ�ϵͳʶ�����յ���Ҫ�����������ļ�ϵͳ������
3.IRP_MN_USER_FS_REQUEST����ʱ���Դ�
Irpsp->Parameters.FileSystemControl.FsControlCode�õ�һ�������룬
��������ΪFSCTL_DISMOUNT_VOLUMEʱ��˵������һ�������ڽ���أ�
��u�̵��ֹ��γ������ᵼ�·�����������ݲ���
����:
�Լ��Ĺ����豸(�����ļ�ϵͳ�����豸��)
irp����
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
		//���������
		case IRP_MN_MOUNT_VOLUME:
			return	_FsFilterControlMountVolume(
				_pDeviceObject , _pIrp );

			//�ļ�ϵͳʶ�����յ��ļ����ļ�ϵͳ������
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

							//��ӡ��Ϣ
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

	  //����Irp�����·��²��豸
	IoSkipCurrentIrpStackLocation( _pIrp );
	return	IoCallDriver(
		((PFSFILTER_DEVICE_EXTENSION)_pDeviceObject->DeviceExtension)->pLowerFsDeviceObject ,
		_pIrp );
}


/*
�ú���������������
ͨ�������������·����ļ�ϵͳ,�����������Ի���ļ�ϵͳ������
���豸,Ȼ���������豸����
����:
�Լ��Ĺ����豸(�����ļ�ϵͳ�����豸֮��)
irp����
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
	//��ÿ��豸����
	pStorageStackDeviceObject =
		pIrpStack->Parameters.MountVolume.Vpb->RealDevice;

	//�ж��Ƿ���һ����Ӱ�����豸,���󶨾�Ӱ
	status =
		_FsFilterIsShadowCopyVolume(
		pStorageStackDeviceObject ,
		&bIsShadowCopyVolume );
	if (NT_SUCCESS( status ) &&
		bIsShadowCopyVolume)
	{
		//��ӡ��Ӱ�豸
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

		//�����������·����ļ�ϵͳ�Լ�����,����,���Ǿ�Ӱ
		IoSkipCurrentIrpStackLocation( _pIrp );
		return	IoCallDriver(
			pFilterControlDevExt->pLowerFsDeviceObject ,
			_pIrp );

	} // end if (NT_SUCCESS( status ) && bIsShadowCopyVolume)

	  //���Ǿ�Ӱ,Ҫ��

	  //�������Լ��Ĺ����豸(����),������vpb�е�DeviceObject
	  //��Ϊ��û�й���,vpb�е�DeviceObject����Ч��
	status =
		IoCreateDevice(
		g_pFsFilterDriverObject ,
		sizeof( FSFILTER_DEVICE_EXTENSION ) ,
		NULL ,	//����
		_pFilterControlDevice->Type ,
		0 ,
		FALSE ,
		&pFilterDeviceObject );
	if (!NT_SUCCESS( status ))
	{
		//��������豸ʧ�ܾͲ����˹��������·�
		//ֱ�����,���ش���
		KdPrint( ("_FsFilterControlMountVolume:\n\
		Error creating filter device object\n\
		status=%x\n" , status) );

		_pIrp->IoStatus.Information = 0;
		_pIrp->IoStatus.Status = status;
		IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
		return	status;
	}

	//��д�豸��չ
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
		&WaitEvent ,	//��ɺ�������Ĳ���
		TRUE ,
		TRUE ,
		TRUE );

	//����IRP���ȴ��¼�������
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
	���ú�����
	irp�������溯���б����
	����󶨲��ɹ�,�½������豸�������溯����ɾ��
	*/
	status = _FsFilterFsControlMountVolumeComplete(
		//_pFilterControlDevice ,
		_pIrp ,
		pFilterDeviceObject );

	return	status;
}


/*
����ɺ��������ļ�ϵͳ�����������������
�������¼���������Ϊ���ź�,�ȴ����¼��Ĵ���ͻ����ִ��
����:
�¼����͵�ָ��
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

	//����STATUS_MORE_PROCESSING_REQUIRED
	//�����IRPҪ�ٴα����
	return	STATUS_MORE_PROCESSING_REQUIRED;
}


/*
�ú����ھ���ɹ��غ� ִ�а�
Ȼ���ٴ����irp
�����ʧ�ܻ�ɾ���½������豸
����:
Irp����
�½��Ĺ����豸���������ļ�ϵͳ���豸��
����ֵ:
�󶨵Ľ��
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

	//���֮ǰ�����vpb
	pvpb = pNewDevExt->pStorageStackDeviceObject->Vpb;

	if (NT_SUCCESS( _pIrp->IoStatus.Status ))
	{
		//���һ��������,ԭ�ӵ��ж��Ƿ�󶨹�һ���豸
		//��ֹ���ΰ�
		ExAcquireFastMutex( &g_FastMutexAttach );
		if (!_FsIsAttachedToDevice(
			pvpb->DeviceObject ,
			&pAttachedDeviceObject ))
		{
			//������������İ�
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
			//�󶨹���
			IoDeleteDevice( _pNewFilterDevice );
			//����Թ����豸������
			ObDereferenceObject( pAttachedDeviceObject );
		} // end if (attached)

		ExReleaseFastMutex( &g_FastMutexAttach );

	} // if (NT_SUCCESS( _pIrp->IoStatus.Status ))
	else
	{
		//������˵������ز��ɹ�
		IoDeleteDevice( _pNewFilterDevice );
	} // end if(NT_SUCCESS(_pIrp->IoStatus.Status))

	  //�ٴ����Irp����
	status = _pIrp->IoStatus.Status;
	IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
	return	status;
}


/*
�ú�������������ж��
Ҫ������ļ�ϵͳ�豸ջ�İ�,�Լ�ɾ���豸
����:
DriverObject�Լ�����������
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

	//ȡ�����ļ�ϵͳ����ĺ����ص�
	IoUnregisterFsRegistrationChange(
		_pDriverObject ,
		_FsChangeCallback );

	/*
	������һ��ѭ��
	�����ڸú����б��������ڴ�,����һ��ֻ��ȡ64���豸����
	��������DevList��,����ȡ��ͻ��˳�ѭ��
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
		����DevList�е��豸,������ǶԵײ��豸�İ�
		��Ҫ�����Լ��Ŀ����豸,�Լ��Ŀ����豸��������Ӧ�ó���
		ͨ�ŵ�,��û�а��κ��豸
		*/
		for (i = 0; i < DevicesCount; i++)
		{
			pDevExt = pDevList[i]->DeviceExtension;
			if (pDevList[i] != g_pFsFilterControlDeviceObject)	//�����豸������
			{
				IoDetachDevice(
					pDevExt->pLowerFsDeviceObject );
			}
		}

		//�����ӳ�5��
		liInterval.QuadPart = 5 * DELAY_ONE_SECOND;
		KeDelayExecutionThread(
			KernelMode ,
			FALSE ,
			&liInterval );

		//�ٴα���,�����ɾ���豸
		for (i = 0; i < DevicesCount; i++)
		{
			//�ж��Ƿ��Լ��Ŀ����豸
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

			//ɾ�����豸,���ҽ����
			//IoEnumerateDeviceObjectList���ӵ�����
			ObDereferenceObject( pDevList[i] );
			IoDeleteDevice( pDevList[i] );
		}

	} // end for(;;)

	  //��Ҫɾ������io��
	pFastIoDispatch = _pDriverObject->FastIoDispatch;
	_pDriverObject->FastIoDispatch = NULL;
	ExFreePool( pFastIoDispatch );

	//ɾ����������
	UNICODE_STRING	Win32Name;

	RtlInitUnicodeString( &Win32Name , L"\\DosDevices\\PowerfulGun_FsProtect" );
	IoDeleteSymbolicLink( &Win32Name );

	//ɾ����������
	_DeleteVirusList();

	//�ر�ע���������
	if(g_hRegistrySub)
	ZwClose( g_hRegistrySub );
}


/*
�ú��������豸�յ��Ĵ�����,
����ǹ����豸���ܵ��ľͳ��Դ�ӡ�򿪵��ļ���
����:
DeviceObject�豸����
pirp����
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

	//�ж��Ƿ����Լ��Ŀ����豸
	if (IS_MY_CONTROL_DEVICE_OBJECT( _pDeviceObject ))
	{
		_pIrp->IoStatus.Status = STATUS_SUCCESS;
		_pIrp->IoStatus.Information = 0;
		IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
		return	STATUS_SUCCESS;
	}

	//���ǿ����豸���ǹ����豸,�������·����ļ�ϵͳȥ��
	IoSkipCurrentIrpStackLocation( _pIrp );
	
	return	IoCallDriver(
		(pDevExt->pLowerFsDeviceObject) ,
		_pIrp );
}


/*
�ú��������豸�յ��Ĺر�����
*/
NTSTATUS	_FsFilterCloseDispatch(
	IN	PDEVICE_OBJECT	_pDeviceObject ,
	IN	PIRP	_pIrp
)
{
	

	//�ж��Ƿ����Լ��Ŀ����豸
	if (IS_MY_CONTROL_DEVICE_OBJECT( _pDeviceObject ))
	{
		PCONTROL_DEVICE_EXTENSION	pDevExt =
			_pDeviceObject->DeviceExtension;

		KdPrint( ("[IRP_MJ_CLOSE]: Close CD0\n") );

		//�ͷ���Դ
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

		//���irp����
		_pIrp->IoStatus.Status = STATUS_SUCCESS;
		_pIrp->IoStatus.Information = 0;
		IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
		return	STATUS_SUCCESS;
	}


	PFSFILTER_DEVICE_EXTENSION	pDevExt =
		_pDeviceObject->DeviceExtension;
	//�����Լ��Ŀ����豸���·�
	IoSkipCurrentIrpStackLocation( _pIrp );

	return IoCallDriver( pDevExt->pLowerFsDeviceObject , _pIrp );

}


/*
�ú������ļ�ϵͳж��ʱ������ļ�ϵͳ�����豸������
����:
FsControlDevice�ļ�ϵͳ�����豸
*/
VOID	_FsFilterDetachFsControlDevice(
	IN	PDEVICE_OBJECT	_pFsControlDevice
)
{
	PDEVICE_OBJECT	pmyFilterDevice;
	PFSFILTER_DEVICE_EXTENSION	pDevExt;

	PAGED_CODE();

	//�õ������豸�Ϸ��İ��豸
	//������豸���Լ����ļ�ϵͳ�����ʱ��󶨵�
	pmyFilterDevice = _pFsControlDevice->AttachedDevice;

	while (pmyFilterDevice != NULL)
	{
		if (IS_MY_DEVICE_OBJECT( pmyFilterDevice ))
		{
			pDevExt = pmyFilterDevice->DeviceExtension;

			//��ӡ���ǰ󶨵��豸��
			KdPrint( ("_FsFilterDetachFsControlDevice:\n\
			Detaching from FsControlDevice:%p\n\
			DeviceName:%wZ\n\
			DeviceType=%s\n" ,
				pDevExt->pLowerFsDeviceObject ,
				&pDevExt->DeviceName ,
				GET_DEVICE_TYPE_NAME( pmyFilterDevice->DeviceType )) );

			//�����,��ɾ���Լ����豸
			IoDetachDevice( _pFsControlDevice );
			IoDeleteDevice( pmyFilterDevice );

			return;
		}

		//���ܵ�ǰ��������豸�����Լ���(����������)
		//��������Ѱ���Լ��Ĺ����豸Ȼ���ж�
		_pFsControlDevice = pmyFilterDevice;
		pmyFilterDevice = pmyFilterDevice->AttachedDevice;

	} // end while
}


/*
��������ļ�ϵͳʶ����,�ú����ͻᴦ��
�ļ�ϵͳ���ص�����,�����·�������
����ɹ���ɾ�������豸
����:
filterDeviceObject:�����ļ�ϵͳʶ�����ϵĹ����豸
PIRP:Irp����
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

	//׼���������·�
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
	//�ȴ��������
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

	//����֮��Ĳ���,�������irp����ɾ���豸
	status =
		_FsFilterFsControlLoadFileSystemComplete(
		_pFilterDeviceObject , _pIrp );

	return	status;
}


/*
���������ļ�ϵͳ�������֮�������,����ļ�ϵͳ���سɹ���ɾ���豸
����:
filterDeviceObject ʶ�����ϵĹ����豸
irp����
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

	//���irp����״̬
	if (!NT_SUCCESS( _pIrp->IoStatus.Status ) &&
		(_pIrp->IoStatus.Status != STATUS_IMAGE_ALREADY_LOADED))
	{
		//����ʧ���˾ͼ򵥵��ٴΰ󶨿�����
		_FsFilterAttachToDeviceStack(
			_pFilterDeviceObject ,
			pDevExt->pLowerFsDeviceObject ,
			&pDevExt->pLowerFsDeviceObject );
		ASSERT( pDevExt->pLowerFsDeviceObject != NULL );
	}
	else
	{
		//���سɹ�������¾�ɾ���豸
		IoDeleteDevice( _pFilterDeviceObject );
	}

	//���Irp����
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

	// ����ǿ����豸��������
	if (IS_MY_CONTROL_DEVICE_OBJECT( DeviceObject ))
		return FALSE;
	// ��������ҵ��豸(Ӱ���豸���ܷ����������)    
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
	// ��������ҵ��豸(Ӱ���豸���ܷ����������)    
	if (!IS_MY_DEVICE_OBJECT( DeviceObject ))
		return FALSE;

	//	return FALSE;	 // add by tanwen.	��Ȥ���ǣ�������������Է���false�����
	// ������false���ᵼ�½�����������ޱȣ���ʱ����ʱ���15�������ϣ���
	// ����ǿ����豸��������

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
����ɺ��������ļ�ϵͳ���Create IRp��������
�����������¼�Ϊ���ź�
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

	//�����¼�
	KeSetEvent( pWaitEvent , IO_NO_INCREMENT , FALSE );

	return	STATUS_MORE_PROCESSING_REQUIRED;
}


/*
�ú���������Ҫ��ӡ�����е��ļ�������ļ���
����:
pIrp����
pFirstDisplayStr��Ҫ���ȴ�ӡ���ַ���
pSuffix��Ҫƥ����ļ���׺��,������ļ����ĺ�׺ƥ��Ż��ӡ
pbIsExe�������ظ��ļ����Ƿ���һ����ִ���ļ�(��׺��exe��dll)
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
		{	//����ƥ���׺ֱ�Ӵ�ӡ
			KdPrint( ("%S\tFileObject->FileName:%wZ\n" ,
				_pFirstDisplayStr,&pFileObject->FileName) );

			return STATUS_SUCCESS;
		}
		
		if (pFileObject->FileName.Length > 4 * 2)
		{
			//��ΪpFileObject->FileName->buffer�е��ַ���������\0��β,����Ҫ
			//���ļ����������Լ��Ļ�����(��\0��β)��,Ϊ��֮��ʹ��wcstr����
			pNameBuffer =
				ExAllocatePoolWithTag(
				NonPagedPool ,
				pFileObject->FileName.Length + sizeof( WCHAR ) ,	//��һĩβ\0
				POOL_TAG );
			if (pNameBuffer == NULL)
				return	STATUS_INSUFFICIENT_RESOURCES;

			RtlZeroMemory( pNameBuffer ,
				pFileObject->FileName.Length + sizeof( WCHAR ) );
			wcsncpy(
				pNameBuffer ,
				pFileObject->FileName.Buffer ,
				pFileObject->FileName.Length / sizeof( WCHAR ) );

			//���ļ�����ƥ���׺�ַ���
			for (ULONG i = 0; _pSuffix[i].SuffixLength != 0; i++)
			{
				if (wcsstr(					//ע��wcstr
					pNameBuffer ,			//����ò����ַ���������\0��β,�ú���������ʱ������(�ڴ����Υ��)
					_pSuffix[i].pSuffix ))
				{
					KdPrint( ("%S\tFileObject->FileName:%wZ\n" ,
						_pFirstDisplayStr , &pFileObject->FileName) );

					//�����־
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

		//ͨ������׺���ж��Ƿ���һ����ִ���ļ�
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
		//���ļ�����û���ļ���,������c:  d:֮�������������
		//KdPrint( ("%S\tNo File Name\n",_pFirstDisplayStr) );
	}


	return	STATUS_SUCCESS;
	/*
	��һ�ε���,�������0,Ŀ��Ϊ�˻�������ֽڴ�С
	status = ObQueryNameString(
	pFileObject ,
	pNameInfor ,
	Length ,
	&Length );
	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
	Length += 16;
	���䳤��
	pNameBuffer = ExAllocatePoolWithTag(
	NonPagedPool ,
	Length,
	POOL_TAG );
	if (pNameBuffer == NULL)
	{
	KdPrint( ("_FsFilterDisplayFileName.ExAllocatePoolTag fail\n") );

	return;
	}

	�ڶ��ε���
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
�ú�������IRP_MJ_READ����
��Ҫ����Ƿ��ж�exe�ļ��������
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
	//������Լ��Ŀ����豸�յ���
		if (IS_MY_CONTROL_DEVICE_OBJECT( _pDeviceObject ))
		{
			//���ز�֧��
			_pIrp->IoStatus.Information = 0;
			_pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
			IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
			return	STATUS_NOT_SUPPORTED;
		}

		//�Ȳ鿴�������ж������Ƿ�Ҫ����
		if (g_Control.ReadControl == FALSE)
			break;

		//�ж�Ŀ���ļ��Ƿ���exe�ļ�����������ض���׺���ļ���
		status = _FsFilterDisplayFileName(
			_pIrp ,
			L"[IRP_MJ_READ]\n" ,
			Suffix ,
			&bIsExeProgram );

		//�жϴ˴β����Ƿ���Ҫ����
		if (pFileObject->FsContext == g_pSkipFileObjectContext)
		{
			KdPrint( ("Skip check this fileobject\n") );
			break;
		}

		//����ǿ�ִ���ļ���Ҫ��һ�����
		if (bIsExeProgram == TRUE &&
			NT_SUCCESS( status ))
		{
			//�����Ҫ���Ŀ�ִ���ļ��Ƿ��в���������
			status = _CheckVirusFile(
				NULL ,
				pFileObject ,
				_pDeviceObject ,
				&bIsVirus );
			if (NT_SUCCESS( status ) && bIsVirus == TRUE)
			{
				//�ǲ���,ɾ��Ŀ�겡���ļ�
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
				//�����־
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

			//ֱ�ӽ���Irp����,�����ļ�ϵͳ��ȡ
				status = STATUS_FILE_CLOSED;
				_pIrp->IoStatus.Status = status;
				_pIrp->IoStatus.Information = 0;
				IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
				return	status;
			}
		} // end if
	} while (FALSE);

	//�������ļ�ϵͳȥ��ȡ
	IoSkipCurrentIrpStackLocation( _pIrp );
	return	IoCallDriver(
		pDevExt->pLowerFsDeviceObject ,
		_pIrp );
}


/*
�ú������Ŀ��exe�����Ƿ��в���������
����:
hFile��ص��ļ����
pFileObject��ص��ļ�����
pDeviceObject�����豸����
pbIsVirus���������Ƿ��ǲ���
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
	{	//�жϵ�ǰ�ļ������Ƿ��Ѿ�����
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

		//��ȡ�ļ�������
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
		//��ӡ�ļ�������
		KdPrint( ("FileData[0]:%x\n\
				FileData[1]:%x\n\
				FileData[2]:%x\n\
				FileData[3]:%x\n" ,
			FileData[0] , FileData[1] , FileData[2] , FileData[3]) );
		//���ļ��������¼��LastFileContext,��Ϊ���һ�η�������
		g_LastFileContext.FileData[0] = FileData[0];
		g_LastFileContext.FileData[1] = FileData[1];
		g_LastFileContext.FileData[2] = FileData[2];
		g_LastFileContext.FileData[3] = FileData[3];

		//�����־
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
		//�ж��Ƿ��ǲ���
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
				//������ͱ��ر����һ�����ǲ���
				*_pbIsVirus = TRUE;
				g_LastFileContext.bIsVirus = TRUE;

				KdPrint( ("###################\n\
							Find Virus:\t%S\n\
							####################\n" , pTempVirusList->VirusInfor.Name) );
				//�����־
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
�ú�����ѯ�ļ���Ϣ
����:
pFileOebjct��ص��ļ�����
pLowerDeviceObject �����豸�²���ļ�ϵͳ���豸
FILE_INFORMATION_CLASS�����ѯ�����
pBuffer�������ز�ѯ�Ľ���Ļ�����
BufferLength �������Ĵ�С
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


	//��ʼ�������ȴ����¼�
	KeInitializeEvent(
		&WaitEvent ,
		SynchronizationEvent ,
		FALSE );

	//����Irp
	pIrp =
		IoAllocateIrp( _pFsDeviceObject->StackSize , FALSE );
	if (pIrp == NULL)
		return	STATUS_INSUFFICIENT_RESOURCES;

	//��дIrp����
	pIrp->AssociatedIrp.SystemBuffer = _pBuffer;
	pIrp->UserEvent = &WaitEvent;
	pIrp->UserIosb = &iosb;
	pIrp->Tail.Overlay.Thread = PsGetCurrentThread();
	pIrp->Tail.Overlay.OriginalFileObject = _pFileObject;
	pIrp->RequestorMode = KernelMode;
	pIrp->Flags = 0;

	//�����²�IrpStack
	pIrpStack = IoGetNextIrpStackLocation( pIrp );
	pIrpStack->MajorFunction = IRP_MJ_QUERY_INFORMATION;
	pIrpStack->DeviceObject = _pFsDeviceObject;
	pIrpStack->FileObject = _pFileObject;
	pIrpStack->Parameters.QueryFile.Length = _BufferLength;
	pIrpStack->Parameters.QueryFile.FileInformationClass =
		_InforClass;

	//������ɺ���
	IoSetCompletionRoutine(
		pIrp ,
		_IrpCompletion ,
		NULL ,
		TRUE ,
		TRUE ,
		TRUE );

	//��������ȴ�����
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
����ɺ�����Irp�������ʱ������
���������¼�
*/
NTSTATUS	_IrpCompletion(
	PDEVICE_OBJECT	_pDeviceObject ,
	PIRP	_pIrp ,
	PVOID	_pContext
)
{
	//�������״̬
	*_pIrp->UserIosb = _pIrp->IoStatus;
	//�����¼�
	KeSetEvent(
		_pIrp->UserEvent ,
		IO_NO_INCREMENT ,
		FALSE );

	//�ͷ�irp��Դ
	IoFreeIrp( _pIrp );

	return	STATUS_MORE_PROCESSING_REQUIRED;
}


/*
�ú���ͨ��ֱ�ӷ���irp������ļ�ϵͳ����ȡ�ļ�����
����:
pFileObject��ص��ļ�����
pFsDeviceObject�ļ�ϵͳ���豸����
pliOffset����ƫ��
Length���Ĵ�С
pBuffer�������ض����ݵĻ�����
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


	//����ԭ��FileObject�е�CurrentOffset
	liCurrentOffset = _pFileObject->CurrentByteOffset;

	//��ʼ���ȴ��¼�
	KeInitializeEvent(
		&WaitEvent ,
		SynchronizationEvent ,
		FALSE );

	//����Irp
	pIrp = IoAllocateIrp(
		_pFsDeviceObject->StackSize ,
		FALSE );
	if (pIrp == NULL)
		return	STATUS_INSUFFICIENT_RESOURCES;

	//��дIrp����
	//�ж��豸��IO��ʽ
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

	//����ʱ����÷ǻ��巽ʽ,��ֹӰ���ļ�������
	pIrp->Flags =
		IRP_DEFER_IO_COMPLETION |
		IRP_READ_OPERATION |
		IRP_NOCACHE;

	//����IrpStack
	pIrpStack = IoGetNextIrpStackLocation( pIrp );

	pIrpStack->MajorFunction = IRP_MJ_READ;
	pIrpStack->MinorFunction = IRP_MN_NORMAL;
	pIrpStack->DeviceObject = _pFsDeviceObject;
	pIrpStack->FileObject = _pFileObject;

	//���ö���ƫ�ƺʹ�С
	pIrpStack->Parameters.Read.ByteOffset = *_pliOffset;
	pIrpStack->Parameters.Read.Key = 0;
	pIrpStack->Parameters.Read.Length = _Length;

	//������ɺ���
	IoSetCompletionRoutine(
		pIrp ,
		_IrpCompletion ,
		NULL ,
		TRUE ,
		TRUE ,
		TRUE );

	//���·���IRp
	status = IoCallDriver( _pFsDeviceObject , pIrp );
	
		KeWaitForSingleObject(
			&WaitEvent ,
			Executive ,
			KernelMode ,
			TRUE ,
			NULL );
	

	//�ͷ�MDL
	if (pMdl)
	{
		IoFreeMdl( pMdl );
	}

	//�ָ�CurrentOffset
	_pFileObject->CurrentByteOffset = liCurrentOffset;

	return	iosb.Status;
}


/*
�ú�����ò����ļ��е�����������������
����:
hFile����ļ����,����ò�����Ч������ʹ�øò��������ļ�
pFileObject����ļ�����,��������irp�����ļ�
pFsDeviceObjectĿ���ļ��������ļ�ϵͳ�豸����
pFiledata�������ض���������,��������
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

		//�Ȳ�ѯ�ļ���С��Ϣ
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
			//���hFile������Ч��ͨ������irp����pFileObject
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

		//��ӡ�ļ���С
		KdPrint( ("FileInformation.AllocationSize=%iBytes\n\
					FileInformation.EndOfFile=%iBytes\n" ,
			pFileInfor->AllocationSize.QuadPart ,
			pFileInfor->EndOfFile.QuadPart) );


		//׼��������
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
				//����SkipFileObject,��Ҫ���ش˴ζ�����,��Ϊzwreadfile�ᷢ��IRP_MJ_READ����
				g_pSkipFileObjectContext = _pFileObject->FsContext;

				//���ļ��ж�����
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
�ú�������IRP_MJ_SET_INFORMATION����
��Ҫ����Ƿ��������ļ��Ĳ���
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

	//����豸Ӧ�����Լ��Ĺ����豸
	ASSERT( IS_MY_DEVICE_OBJECT( _pDeviceObject ) );

	do
	{
		//�Ȳ鿴�������������ļ����������Ƿ�Ҫ����
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

				//��鵱ǰ�����Ƿ�Ϸ�,���Ϸ�ֱ�Ӳ���
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
					//�����־
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

					//���������ڴ�
					status = _KillThread( NULL,pThreadStartAddress,ThreadModuleCodeSize );
					if (!NT_SUCCESS( status ))
					{
						KdPrint( ("_FsFilterSetInformationDispatch.\n\
									\t_KillProcess fail,status=%x\n" , status) );
					}

					//�ǲ������̵�����,ֱ�ӽ������󲻸��ļ�ϵͳ����
					status = STATUS_FILE_CLOSED;
					_pIrp->IoStatus.Status = status;
					_pIrp->IoStatus.Information = 0;
					IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
					return	status;
				}
			}
		} // if (pIrpStack->Parameters.SetFile.FileInformationClass == FileBasicInformation)

	} while (FALSE);

	//�·����²��ļ�ϵͳ�豸
	IoSkipCurrentIrpStackLocation( _pIrp );

	return	IoCallDriver(
		pDevExt->pLowerFsDeviceObject ,
		_pIrp );
}

//
///*
//�ú�����ý�������EPROCESS�е�ƫ��
//*/
//VOID	_GetProcessNameOffset()
//{
//	ULONG	i;
//	PEPROCESS	pCurrentProcess;
//
//	//��������System����������,�õ����̵Ľṹ��
//	pCurrentProcess = PsGetCurrentProcess();
//
//	//�����ַ���"System",����¼ƫ��
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
//�ú���ͨ��ƫ�ƻ�ý�����
//����:
//pProcessName�������ؽ�����
//pRetLength����������Ҫ�Ļ�������С
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
//	//��õ�ǰ���̽ṹ��
//	PCurrentProcess = PsGetCurrentProcess();
//
//	//�ӽṹ���л�ȡ������
//	RtlInitAnsiString(
//		&AnsiName ,
//		(PCHAR)PCurrentProcess + g_ProcessNameOffset );
//
//	//�����ANSIת����UNICODE��Ҫ�Ĵ�С
//	NeedLength = RtlAnsiStringToUnicodeSize( &AnsiName );
//	//�ж�����������ռ��Ƿ��㹻����
//	if (NeedLength > _pProcessName->MaximumLength)
//	{
//		//�����ͷ�������Ҫ���ֽ���
//		if (_pRetLength != NULL)
//			*_pRetLength = NeedLength;
//		return	STATUS_BUFFER_TOO_SMALL;
//	}
//
//	//ת����UNICODE
//	RtlAnsiStringToUnicodeString(
//		_pProcessName ,
//		&AnsiName ,
//		FALSE );
//	return	STATUS_SUCCESS;
//}


/*
�ú����������յ����ļ��������صĲ���ʱ����
��鷢������Ľ����Ƿ�Ϸ�,����ǲ������̾�ɾ�����ִ���ļ�
����:
pDeviceObject�Լ��Ĺ����豸����
pKThreadĿ���߳̽ṹ��
pKProcessĿ����̽ṹ��
pbIsVirus���������Ƿ��ǲ�������
pThreadStartAddress�����ش��̵߳Ĵ���ҳ��ʼ��ַ
pThreadModulePageSize�����ش��߳�������ģ���ҳ��С
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
	//��һ�ε���Ϊ�˻�û�������С
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
		
		//�ڶ��ε�����������ַ���
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

		//��ӡ�߳�ģ����
		KdPrint( ("ThreadModulePath:%wZ\n" , &ThreadModuleName) );
		////�����־
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
		//�򿪿�ִ���ļ�,Ϊ�˻�����ļ����
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

		//ͨ���ļ��������ļ�����
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

		//�����̵�exe�ļ��Ƿ��ǲ����ļ�,�ݲ�ʹ��hFile����
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

		//������̵�exe�ǲ�����ɾ����exe
		if (*_pbIsVirus == TRUE)
		{
			//ɾ��Ŀ�겡�����̵Ŀ�ִ���ļ�
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
			////�����־
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

	//�رվ��
	if (hImageFile)
	{
		ZwClose( hImageFile );
		//������ļ����������
		if (pImageFileObject)
			ObDereferenceObject( pImageFileObject );
	}
	//�ͷ��ڴ�
	if (ThreadModuleName.Buffer)
		ExFreePool( ThreadModuleName.Buffer );

	return	status;
}


/*
�ú�������ɱ��Ŀ�����
����:
pProcessĿ����̽ṹ��ָ��
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

	//����Ŀ�����
	KeStackAttachProcess(
		_pKProcess ,
		pApcState );
	//�����ڴ����
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
			if (i > 0x1000000)  //����ô���㹻�ƻ�����������  
				break;
		}
	}

	//�лؽ���
	KeUnstackDetachProcess( pApcState );

	return	STATUS_SUCCESS;
}


/*
�ú�������ɱ����ǰ�߳�
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

	//����Ŀ�����
		KeStackAttachProcess(
			_pKProcess ,
			pApcState );
	}

	//�ر�д����
	//KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0( cr0 );
	//_disable();	//�����ж�

	//�߳��ڴ����
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

	//��д����
	cr0 = __readcr0();
	cr0 |= 0x10000;
	//_enable();//�����ж�
	__writecr0( cr0 );
	//KeLowerIrql( irql );

	if (_pKProcess)
	{
		//�лؽ���
		KeUnstackDetachProcess( pApcState );
	}

	return	STATUS_SUCCESS;
}


/*
�ú�������IRP_MJ_WRITE�ļ�ϵͳд����
��Ҫ����Ƿ���д��ִ���ļ��Ĳ���
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


	//������Լ��Ŀ����豸�յ���
	if (IS_MY_CONTROL_DEVICE_OBJECT( _pDeviceObject ))
	{
		//���ز�֧��
		_pIrp->IoStatus.Information = 0;
		_pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
		IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
		return	STATUS_NOT_SUPPORTED;
	}

	//�Ȳ鿴��������д�����Ƿ�Ҫ����
	if (g_Control.WriteControl == FALSE)
		goto SEND_NEXT;

	//�ж�Ŀ���ļ��Ƿ��ǿ�ִ���ļ������
	status = _FsFilterDisplayFileName(
		_pIrp ,
		L"[IRP_MJ_WRITE]\n" ,
		Suffix,
		&bIsExeProgram );
	if (NT_SUCCESS( status ) && bIsExeProgram == TRUE)
	{
	//��鵱ǰ�����Ƿ�Ϸ�,���Ϸ�ֱ�Ӳ���
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
			//�����־
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

		//�����ڴ�
			status = _KillThread( NULL , pThreadStartAddress , ThreadModuleCodeSize );
			if (!NT_SUCCESS( status ))
			{
				KdPrint( ("_FsFilterSetInformationDispatch.\n\
									\t_KillProcess fail,status=%x\n" , status) );
			}

			//ɾ������д��exe�ļ�
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
			//�����־
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


			//�ǲ������̵�����,ֱ�ӽ������󲻸��ļ�ϵͳ����
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
�ú������Ŀ����̵�������ִ���ļ���
����:
pKprocessĿ����̽ṹ��
pRetImagePath������������·����
pRetNeedLength�������ػ�������Ҫ�Ĵ�С
pThreadStartAddress�����ش��̵߳Ĵ���ҳ��ʼ��ַ
pThreadModulePageSize�����ش��߳�������ģ���ҳ��С
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
		//����ǵ�һ�ε��þ���Ҫ���ZwQueryInformationThread�ĺ���ָ��
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

		//���Ŀ���̵߳ľ��,�ú��������Ӷ��������
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

		//���Ŀ����̵ľ��,�ú��������Ӷ��������
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
		////�Ȼ�û���������
		//status = ZwQueryInformationThread(
		//	hThread ,
		//	ThreadBasicInformation ,
		//	NULL ,
		//	0 ,
		//	&RetLength );
		//if (status != STATUS_INFO_LENGTH_MISMATCH)
		//	return	status;

		////��������������С�Ƿ��㹻,������ͨ��RetNeedLength����������Ҫ�Ĵ�С
		//if (_pRetImagePath->MaximumLength < (RetLength - sizeof( UNICODE_STRING )))
		//{
		//	if (_pRetNeedLength)
		//		*_pRetNeedLength = RetLength - sizeof( UNICODE_STRING );

		//	status = STATUS_BUFFER_TOO_SMALL;
		//	break;
		//}

		////���仺�����ڴ�
		//pBuffer = ExAllocatePoolWithTag(
		//	NonPagedPool ,
		//	RetLength ,
		//	POOL_TAG );
		//if (pBuffer == NULL)
		//{
		//	status = STATUS_INSUFFICIENT_RESOURCES;
		//	break;
		//}

		//����߳���ʼ��ַ
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

		//��һ�ε��û�û�������С
		status = ZwQueryVirtualMemory(
			hProcess ,
			pThreadStartAddress ,
			2 ,
			NULL ,
			0 ,
			&RetLength );
		if (!NT_SUCCESS( status ))
		{
		//��������������С�Ƿ��㹻,������ͨ��RetNeedLength����������Ҫ�Ĵ�С
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

		//���仺����
		pBuffer = ExAllocatePoolWithTag(
			NonPagedPool ,
			RetLength ,
			POOL_TAG );
		if (pBuffer == NULL)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		//�ڶ����������ģ����
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
			//���������
			RtlCopyUnicodeString( _pRetModulePath , pModuleName );
		}

		//�ٻ��ģ�����ռ��ҳ����Ϣ
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
		
		//�����߳���ʼ��ַ��ģ��ռ��ҳ���С
		if (_pThreadStartAddress)
			*_pThreadStartAddress = MemBasicInfor.BaseAddress;
		if (_pThreadModuleCodeSize)
			*_pThreadModuleCodeSize = MemBasicInfor.RegionSize;

		
	} while (FALSE);

	//�������,��ObOpenObjectByPointer���ӵ�
	ZwClose( hThread );
	ZwClose( hProcess );

	//�ͷ��ڴ�
	if (pBuffer)
		ExFreePool( pBuffer );

	return	status;
}


/*
�ú���ͨ������Irp�����ļ����԰���ɾ��
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

	//��ʼ���ȴ��¼�
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

	//�����ɾ���ļ��Ĳ�����Ҫ��������
	if (_InforClass == FileDispositionInformation &&
		((PFILE_DISPOSITION_INFORMATION)_pBuffer)->DeleteFile == TRUE)
	{
		if (_pFileObject->SectionObjectPointer)
		{
			//�ļ�ϵͳ������2��ֵ�ж��ļ��Ƿ���������,����2��ֵΪ0����ɾ���ļ�
			_pFileObject->SectionObjectPointer->ImageSectionObject = 0;
			_pFileObject->SectionObjectPointer->DataSectionObject = 0;
		}
	}

	//������ɺ���
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
�ú�������IRP_MJ_DEVICE_CONTROL����
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
	{//������Լ��Ŀ����豸�յ���
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
					//�رվ��
					//ZwClose( hUserEvent );
					break;
				}

			case IOCTL_GetShareMemory:
				{
					if (pDevExt->pSharedAddress)
					{
						//��ӳ��ĵ�ַ���ظ�Ӧ�ó���
						*(PVOID*)(_pIrp->AssociatedIrp.SystemBuffer) = pDevExt->pSharedAddress;
						KdPrint( ("[IOCTL_GetShareMemory]: pSharedAddress=%x\n" , pDevExt->pSharedAddress) );
						break;
					}

					__try
					{
						pDevExt->pClientLog =
							ExAllocatePoolWithTag(
							NonPagedPool ,
							sizeof(ULONG) + 1024 ,	//ClientLog����������ܴ�512�����ַ�
							POOL_TAG );
						if (pDevExt->pClientLog == NULL)
						{
							status = STATUS_INSUFFICIENT_RESOURCES;
							break;
						}

						//��ʼ��������Ϊ0
						RtlZeroMemory(
							pDevExt->pClientLog ,
							sizeof(ULONG) + 1024 );

						//����һ��MDL������黺����
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

						//����mdl���ݽṹ,���������ڴ�������ڴ�
						MmBuildMdlForNonPagedPool( pDevExt->pMdlLog );

						//ӳ����ڴ������ַ
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

						//��ӳ��ĵ�ַ���ظ�Ӧ�ó���
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
						//�鿴�Ƿ�������ͬ���ƵĲ��������ڲ���������
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
								//�����־
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

						//�����һ���ļ���������Ϊ����¼�벡������
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
						//��������
						InsertTailList( &g_VirusListHead , &pTempVirusList->ListEntry );

						//����ע���
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
							g_hRegistrySub ,	//ע���Virus����
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

						//��ע������ü�ֵ
						RtlInitUnicodeString(
							&Name , L"Number" );	//���ü���Number
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
							&Name , L"FileData[0]" );	//���ü���FileData[0]
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
							&Name , L"FileData[1]" );	//���ü���FileData[1]
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
							&Name , L"FileData[2]" );	//���ü���FileData[2]
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
							&Name , L"FileData[3]" );	//���ü���FileData[3]
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

						//���رն�ע�����������
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
					ULONG	Number;	//Ҫȡ����ǵĲ����ı��
					PVIRUS_LIST	pTempVirusList;
					UNICODE_STRING	VirusName;
					OBJECT_ATTRIBUTES	ObjAttr;
					HANDLE	hRegistry;

					Number = *(PULONG)(_pIrp->AssociatedIrp.SystemBuffer);
					pTempVirusList = (PVIRUS_LIST)(g_VirusListHead.Blink);	//���β������
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
					//���������Ƴ�
					(pTempVirusList->ListEntry.Blink)->Flink = pTempVirusList->ListEntry.Flink;	//ǰһ����Flinkָ����һ������
					(pTempVirusList->ListEntry.Flink)->Blink = pTempVirusList->ListEntry.Blink;	//��һ����Blinkָ��ǰһ������

					//��ע�����ɾ��
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
					//ɾ������
					status = ZwDeleteKey( hRegistry );
					if (!NT_SUCCESS( status ))
					{
						KdPrint( ("[IOVTL_VirusUnset]:ZwDeleteKey fail,status=%x\n" , status) );
						break;
					}

					ZwClose( hRegistry );
					//�ͷ�����
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
						//֪ͨӦ�ó����¼���ӡ���
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

						//֪ͨӦ�ó����¼���ӡ���
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
		//�������
		_pIrp->IoStatus.Status = status;
		_pIrp->IoStatus.Information = RetLength;
		IoCompleteRequest( _pIrp , IO_NO_INCREMENT );
		return	status;

	} // end if (IS_MY_CONTROL_DEVICE_OBJECT( _pDeviceObject ))

	//�����Լ������豸��������·�
	PFSFILTER_DEVICE_EXTENSION	pDevExt =
		_pDeviceObject->DeviceExtension;

	IoSkipCurrentIrpStackLocation( _pIrp );
	return	IoCallDriver(
		pDevExt->pLowerFsDeviceObject ,
		_pIrp );
}


/*
�ú�����ʼ����������,ע����������ʱҪ�ͷŲ�������ռ�õ��ڴ�
*/
NTSTATUS	_InitVirusList()
{
	PVIRUS_LIST	pTempVirusList;
	ULONG	i;
	NTSTATUS	status;

	//��ʼ������ͷ
	InitializeListHead( &g_VirusListHead );

	//Ĭ���ȴӱ��ز�����¼����Ϣ
	for (i = 0; LocalVirus[i].Name[0] != 0; i++)
	{
		//�����ڴ�
		pTempVirusList = ExAllocatePoolWithTag(
			NonPagedPool ,
			sizeof( VIRUS_LIST ) ,
			POOL_TAG );
		if (pTempVirusList == NULL)
		{
			return	STATUS_INSUFFICIENT_RESOURCES;
		}

		//�����ز�������Ĳ�����Ϣ������������
		pTempVirusList->Number = i;
		wcscpy_s( pTempVirusList->VirusInfor.Name , 32 , LocalVirus[i].Name );
		//������������
		pTempVirusList->VirusInfor.FileData[0] = LocalVirus[i].FileData[0];
		pTempVirusList->VirusInfor.FileData[1] = LocalVirus[i].FileData[1];
		pTempVirusList->VirusInfor.FileData[2] = LocalVirus[i].FileData[2];
		pTempVirusList->VirusInfor.FileData[3] = LocalVirus[i].FileData[3];

		//������ʱ�ڵ��������
		InsertTailList( &g_VirusListHead , &pTempVirusList->ListEntry );
	}
	pTempVirusList = NULL;
	//�ٴ��Զ���ע�����¼�벡����Ϣ
	ULONG	RetLen;
	PKEY_FULL_INFORMATION	pKeyFullInfor=NULL;
	//��һ�ε���ZwQueryKey,Ϊ�˻�ȡKEY_FULL_INFORMAITON�ĳ���
		ZwQueryKey(
			g_hRegistrySub ,//������
			KeyFullInformation ,
			NULL , 0 ,
			&RetLen );
		pKeyFullInfor =
			ExAllocatePoolWithTag(
			NonPagedPool , RetLen , POOL_TAG );
		if (pKeyFullInfor == NULL)
			return	STATUS_INSUFFICIENT_RESOURCES;

		//�ڶ��ε���������ȡKEY_FULL_INFORMATION����
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
				//��һ�ε���ZwEnumerateKey,Ϊ�˻�ȡKEY_BASIC_INFORMATION���ݳ���
				ZwEnumerateKey(
					g_hRegistrySub ,
					i ,
					KeyBasicInformation ,
					NULL , 0 ,
					&RetLen );
				pKeyBasicInfor =
					ExAllocatePoolWithTag(
					NonPagedPool , RetLen + sizeof( WCHAR ) , POOL_TAG );//+2��ֹ��õ�����������
				if (pKeyBasicInfor == NULL)
					break;
				//��ֹ��õ�����������,�ȶԻ���������
				RtlZeroMemory( pKeyBasicInfor , RetLen + sizeof( WCHAR ) );

				//�ڶ��ε���ZwEnumerateKey,Ϊ�˻�ȡKEY_BASIC_INFORMATION����
				status = ZwEnumerateKey(
					g_hRegistrySub ,
					i ,
					KeyBasicInformation ,
					pKeyBasicInfor ,
					RetLen ,
					&RetLen );
				if (!NT_SUCCESS( status ))
					break;
				//����һ������
				pTempVirusList = ExAllocatePoolWithTag(
					NonPagedPool , sizeof( VIRUS_LIST ) , POOL_TAG );
				if (pTempVirusList == NULL)
					break;

				wcscpy_s(
					pTempVirusList->VirusInfor.Name ,
					32 ,
					pKeyBasicInfor->Name );
				//�򿪸�����

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

				//ͨ�������ü�ֵ
				
				pKeyValuePartialInfor = ExAllocatePoolWithTag(
					NonPagedPool , sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 16 , POOL_TAG );
				if (pKeyValuePartialInfor == NULL)
					break;
				RtlZeroMemory(	//��ֹ����
					pKeyValuePartialInfor , 
					sizeof( KEY_VALUE_PARTIAL_INFORMATION ) + 16 );

				//���Number�ļ�ֵ
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
				{	//��ȡ���ֵ���ɹ���Ĭ��ʹ���������ڵ�ı��+1
					pTempVirusList->Number =
						((PVIRUS_LIST)g_VirusListHead.Blink)->Number + 1;
				}
				pTempVirusList->Number = *(PULONG)pKeyValuePartialInfor->Data;

				//���FileData[0]�ļ�ֵ
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

				//���FileData[1]�ļ�ֵ
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

				//���FileData[2]�ļ�ֵ
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

				//���FileData[3]�ļ�ֵ
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

				//���ýڵ��������
				InsertTailList( &g_VirusListHead , &pTempVirusList->ListEntry );
				pTempVirusList = NULL;	//����NULL�����finally���б��ͷ�

			} // try
			__finally	//����ִ����try��ͻ�ִ��finally��,����break���ִ��ʱҲ��ִ��finally���еĴ���
			{
				//finally�����þ����ͷ���Դ
				if (pKeyBasicInfor)
					ExFreePool( pKeyBasicInfor );
				if (pTempVirusList)	//����ִ����try��pTempVirusList����NULL,����ִ���ͷ�,ֻ�г���break��ʱ����ͷ�
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
�ú�������ɾ����������,�ͷ���ռ�õ��ڴ�
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
		//��β��ɾ��һ��Ԫ��
		pTempVirusList =
			(PVIRUS_LIST)RemoveTailList( &g_VirusListHead );

		ExFreePool( pTempVirusList );
	}

	return	STATUS_SUCCESS;
}

