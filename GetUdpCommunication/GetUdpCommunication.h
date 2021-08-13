#pragma once
// Define values.
#define SystemHandleInformation     0x10
#define ObjectNameInformation       1
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xc0000004L)

#define VALID_HANDLE(handle) (handle != INVALID_HANDLE_VALUE && handle != 0)

// Define important functions.
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	ULONG   UniqueProcessId;
	UCHAR   ObjectTypeIndex;
	UCHAR   HandleAttributes;
	USHORT  HandleValue;
	PVOID   Object;
	ULONG   GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG                           NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO  Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION
{
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef long (*NTDUPLICATEOBJECT)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, BOOLEAN, ULONG);
typedef NTSTATUS(*NTQUERYSYSTEMINFORMATION)(
	ULONG   SystemInformationClass,
	PVOID   SystemInformation,
	ULONG   SystemInformationLength,
	PULONG  ReturnLength);
typedef NTSTATUS(*NTQUERYOBJECT)(
	HANDLE                   Handle,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID                    ObjectInformation,
	ULONG                    ObjectInformationLength,
	PULONG                   ReturnLength
	);

NTDUPLICATEOBJECT           pNtDuplicateObject;
NTQUERYSYSTEMINFORMATION    pNtQuerySystemInformation;
NTQUERYOBJECT               pNtQueryObject;

// Prototypes.
bool LoadFunctions();
std::list<DWORD> GetProcesses();
SOCKET GetSocket(DWORD pid);