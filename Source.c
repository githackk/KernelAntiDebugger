#pragma once
#define DEBUG_MSG_LEVEL DPFLTR_INFO_LEVEL

#include <ntifs.h>
#include <ntddk.h>

#define arraysize(p) (sizeof(p)/sizeof((p)[0]))
#define PROCESS_TERMINATE         0x0001  
#define PROCESS_VM_OPERATION      0x0008  
#define PROCESS_VM_READ           0x0010  
#define PROCESS_VM_WRITE          0x0020 
#define PROCESS_READ_CONTROL  0x00020000L
#define PROCESS_QUERY_INFORMATION 0x0400
#define PROCESS_SET_INFORMATION 0x0200
#define PROCESS_CREATE_THREAD 0x0002
#define PROCESS_CREATE_PROCESS 0x0080
#define PROCESS_DUP_HANDLE 0x0040
#define SYNCHRONIZE 0x00100000L
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT pDevice;
	UNICODE_STRING ustrDeviceName; // Имя устройства
	UNICODE_STRING ustrSymLinkName; // Имя символьной ссылки
} DEVICE_EXTENSION, * PDEVICE_EXTENSION; // Информационная структура расширения устройства


typedef struct _LDR_DATA_TABLE_ENTRY64
{
	LIST_ENTRY64    InLoadOrderLinks;
	LIST_ENTRY64    InMemoryOrderLinks;
	LIST_ENTRY64    InInitializationOrderLinks;
	PVOID            DllBase;
	PVOID            EntryPoint;
	ULONG            SizeOfImage;
	UNICODE_STRING    FullDllName;
	UNICODE_STRING     BaseDllName;
	ULONG            Flags;
	USHORT            LoadCount;
	USHORT            TlsIndex;
	PVOID            SectionPointer;
	ULONG            CheckSum;
	PVOID            LoadedImports;
	PVOID            EntryPointActivationContext;
	PVOID            PatchInformation;
	LIST_ENTRY64    ForwarderLinks;
	LIST_ENTRY64    ServiceTagLinks;
	LIST_ENTRY64    StaticLinks;
	PVOID            ContextInformation;
	ULONG64            OriginalBase;
	LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;


NTSTATUS CreateDevice(IN PDRIVER_OBJECT pDrvObj); // Создать подпрограмму устройства
void UnloadDriver(IN PDRIVER_OBJECT pDrvObj); // Функция выгрузки диска

NTSTATUS ProtectProcess(); // Защита процесса
OB_PREOP_CALLBACK_STATUS MyCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation); // Функция обратного вызова
char* GetProcessNameByProcessID(HANDLE pid); // Получить имя процесса



UCHAR* PsGetProcessImageFileName(PEPROCESS EProcess);

BOOLEAN pre = FALSE;

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverOb, IN PUNICODE_STRING pRegistryPath)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_MSG_LEVEL, "Начать загрузку драйвера");
	NTSTATUS status = 0;
	pDriverOb->DriverUnload = UnloadDriver;

	status = CreateDevice(pDriverOb);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_MSG_LEVEL, "Загрузка драйвера завершена");

	PLDR_DATA_TABLE_ENTRY64 ldrDataTable;
	ldrDataTable = (PLDR_DATA_TABLE_ENTRY64)pDriverOb->DriverSection;
	ldrDataTable->Flags |= 0x20; // Более MmVerifyCallbackFunction

	status = ProtectProcess(); // реализовать обратный вызов объекта
	if (NT_SUCCESS(status))
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_MSG_LEVEL, "Функция обратного вызова при регистрации прошла успешно");
		pre = TRUE;
	}
	else
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_MSG_LEVEL, "Не удалось зарегистрировать фукнцию обратного вызова");
	return status;
}



PVOID obHandle; // Сохранить дескриптор обратного вызова

NTSTATUS ProtectProcess()
{

	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;

	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"321000");

	memset(&opReg, 0, sizeof(opReg)); // Инициализировать структурную переменную

	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;

	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)(&MyCallback); // Зарегистрировать указатель функции обратного вызова

	obReg.OperationRegistration = &opReg; // Обратите внимание на этот оператор
	return ObRegisterCallbacks(&obReg, &obHandle); // Зарегистрировать функцию обратного вызова
}

OB_PREOP_CALLBACK_STATUS MyCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	HANDLE pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
	char* szProcName[16];
	UNREFERENCED_PARAMETER(RegistrationContext);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_MSG_LEVEL, "szProcName: %d", szProcName);

	strcpy(&szProcName, GetProcessNameByProcessID(pid));
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_MSG_LEVEL, "szProcName: %d", szProcName);
	if (strcmp(szProcName, "test.exe") == 0)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_MSG_LEVEL, "is test.exe!!!!!");
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DEBUG_MSG_LEVEL, "pid: %d", pid);
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_READ_CONTROL) == PROCESS_READ_CONTROL)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_READ_CONTROL;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_QUERY_INFORMATION) == PROCESS_QUERY_INFORMATION)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_INFORMATION;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_SET_INFORMATION) == PROCESS_SET_INFORMATION)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SET_INFORMATION;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_CREATE_THREAD) == PROCESS_CREATE_THREAD)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_CREATE_PROCESS) == PROCESS_CREATE_PROCESS)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_PROCESS;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_DUP_HANDLE) == PROCESS_DUP_HANDLE)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_DUP_HANDLE;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & SYNCHRONIZE) == SYNCHRONIZE)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~SYNCHRONIZE;
			}
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_QUERY_LIMITED_INFORMATION) == PROCESS_QUERY_LIMITED_INFORMATION)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;
			}
		}
	}
	return OB_PREOP_SUCCESS;
}

char* GetProcessNameByProcessID(HANDLE pid)
{
	NTSTATUS status;
	PEPROCESS EProcess = NULL;
	status = PsLookupProcessByProcessId(pid, &EProcess);

	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}
	ObDereferenceObject(EProcess);
	return (char*)PsGetProcessImageFileName(EProcess);
}



NTSTATUS CreateDevice(
	IN PDRIVER_OBJECT pDriverObject) // Инициализировать объект устройства для возврата в состояние инициализации
{
	NTSTATUS status;
	PDEVICE_OBJECT pDevObj;
	PDEVICE_EXTENSION pDevExt;

	// Создать имя устройства
	UNICODE_STRING devName;
	RtlInitUnicodeString(&devName, L"\\Device\\ObCALL");

	// Создать устройство
	status = IoCreateDevice(pDriverObject,
		sizeof(DEVICE_EXTENSION),
		&devName,
		FILE_DEVICE_UNKNOWN,
		0, TRUE,
		&pDevObj);
	if (!NT_SUCCESS(status))
		return status;

	pDevObj->Flags |= DO_BUFFERED_IO;
	pDevExt = (PDEVICE_EXTENSION)pDevObj->DeviceExtension;
	pDevExt->pDevice = pDevObj;
	pDevExt->ustrDeviceName = devName;
	// Создать символическую ссылку
	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&symLinkName, L"\\??\\Object");
	pDevExt->ustrSymLinkName = symLinkName;
	status = IoCreateSymbolicLink(&symLinkName, &devName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}
	return STATUS_SUCCESS;
}


void UnloadDriver(IN PDRIVER_OBJECT pDriverObject) // Выгрузка операции драйвера
{
	PDEVICE_OBJECT	pNextObj;
	KdPrint(("Enter DriverUnload\n"));
	if (pre) // Если функция обратного вызова успешно зарегистрирована, удалите обратный вызов
		ObUnRegisterCallbacks(obHandle);
	KdPrint(("Удаленный обратный вызов"));
	pNextObj = pDriverObject->DeviceObject;
	while (pNextObj != NULL)
	{
		PDEVICE_EXTENSION pDevExt = (PDEVICE_EXTENSION)
			pNextObj->DeviceExtension;

		// Удалить символическую ссылку
		UNICODE_STRING pLinkName = pDevExt->ustrSymLinkName;
		IoDeleteSymbolicLink(&pLinkName);
		pNextObj = pNextObj->NextDevice;
		IoDeleteDevice(pDevExt->pDevice);
	}
	KdPrint(("Драйвер был удален!"));
}