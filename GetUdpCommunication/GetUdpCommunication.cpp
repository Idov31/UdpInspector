#include "stdafx.h"
#include "GetUdpCommunication.h"

int main()
{
	if (!LoadFunctions()) {
		std::cout << "Failed to initialize critical functions, exiting." << std::endl;
		return -1;
	}

	// Getting the processes that communicates via UDP.
	std::list<DWORD> processes = GetProcesses();

	for (DWORD pid : processes) {
		std::cout << pid << std::endl;
		GetSocketAndPrint(pid);
	}
	return 0;
}

bool LoadFunctions() {
	WORD    wVersionRequested;
	WSADATA WsaData;
	INT     wsaErr;

	// Initialise the socket.
	wVersionRequested = MAKEWORD(2, 2);
	wsaErr = WSAStartup(wVersionRequested, &WsaData);

	if (wsaErr != 0) {
		return false;
	}

	// Loading the functions
	pNtDuplicateObject = (NTDUPLICATEOBJECT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDuplicateObject");
	pNtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
	pNtQueryObject = (NTQUERYOBJECT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");

	if (VALID_HANDLE(pNtDuplicateObject) && VALID_HANDLE(pNtQuerySystemInformation) && VALID_HANDLE(pNtQueryObject)) {
		return true;
	}
	else {
		WSACleanup();
		return false;
	}
}

std::list<DWORD> GetProcesses() {
	// Reference: https://github.com/w4kfu/whook/blob/master/src/network.cpp

	std::list<DWORD> lmib;
	PMIB_UDPTABLE_OWNER_PID pmib;
	DWORD dwSize = 0;
	DWORD dwRetVal;

	// Allocating size.
	pmib = (PMIB_UDPTABLE_OWNER_PID)malloc(sizeof(MIB_UDPTABLE_OWNER_PID));
	if (pmib == NULL) {
		std::cerr << "Failed to allocate memory: " << GetLastError() << std::endl;
		return lmib;
	}
	dwSize = sizeof(MIB_UDPTABLE_OWNER_PID);

	// Checking if allocated enough space.
	if ((dwRetVal = GetExtendedUdpTable(pmib, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0)) == ERROR_INSUFFICIENT_BUFFER) {
		free(pmib);
		pmib = (PMIB_UDPTABLE_OWNER_PID)malloc(dwSize);

		if (pmib == NULL) {
			std::cerr << "Failed to allocate memory: " << GetLastError() << std::endl;
			return lmib;
		}
	}

	// Filling up the table.
	dwRetVal = GetExtendedUdpTable(pmib, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);

	if (dwRetVal != 0) {
		std::cerr << "Failed to achieve the Udp table:  " << GetLastError() << std::endl;
		return lmib;
	}

	// Removing the duplications.
	for (DWORD i = 0; i < pmib->dwNumEntries; i++) {
		bool add = true;

		if (pmib->table[i].dwOwningPid == 4)
			continue;

		for (DWORD pid : lmib) {
			if (pid == pmib->table[i].dwOwningPid) {
				add = false;
				break;
			}
		}

		if (add)
			lmib.push_back(pmib->table[i].dwOwningPid);
	}
	free(pmib);
	return lmib;
}

void GetSocketAndPrint(DWORD pid)
{
	PSYSTEM_HANDLE_INFORMATION  pSysHandleInfo = NULL;
	POBJECT_NAME_INFORMATION    pObjNameInfo = NULL;
	ULONG SystemInformationLength = 0;
	ULONG ObjectInformationLength = 0;
	ULONG ReturnLength;
	HANDLE TargetHandle = INVALID_HANDLE_VALUE;
	SOCKET TargetSocket = INVALID_SOCKET;
	NTSTATUS ntStatus;
	PCWSTR pcwDeviceAfd = L"\\Device\\Afd";
	INT WsaErr;
	WSAPROTOCOL_INFOW WsaProtocolInfo = { 0 };

	// Duplicating the process handle.
	HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);

	if (!VALID_HANDLE(hProcess)) {
		std::cerr << "Failed to open process " << pid << " because: " << GetLastError() << std::endl;
		return;
	}

	pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)calloc(SystemInformationLength, sizeof(UCHAR));

	if (!pSysHandleInfo) {
		std::cerr << "Failed to allocate buffer for system handles: " << GetLastError() << std::endl;
		return;
	}

	// Getting the handles for the process.
	while (pNtQuerySystemInformation(SystemHandleInformation,
		pSysHandleInfo,
		SystemInformationLength,
		&ReturnLength) == STATUS_INFO_LENGTH_MISMATCH) {
		free(pSysHandleInfo);
		SystemInformationLength = ReturnLength;
		pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)calloc(SystemInformationLength, sizeof(UCHAR));

		if (!pSysHandleInfo) {
			std::cerr << "Failed to allocate buffer for system handles: " << GetLastError() << std::endl;
			return;
		}
	}

	if (!pSysHandleInfo) {
		CloseHandle(TargetHandle);
		return;
	}

	// Iterating the handles.
	for (size_t i = 0; i < pSysHandleInfo->NumberOfHandles; i++) {
		if (pSysHandleInfo->Handles[i].ObjectTypeIndex != 0x24) {
			ntStatus = pNtDuplicateObject(hProcess,
				(HANDLE)pSysHandleInfo->Handles[i].HandleValue,
				GetCurrentProcess(),
				&TargetHandle,
				PROCESS_ALL_ACCESS,
				FALSE,
				DUPLICATE_SAME_ACCESS);

			if (ntStatus == STATUS_SUCCESS) {
				pObjNameInfo = (POBJECT_NAME_INFORMATION)calloc(ObjectInformationLength, sizeof(UCHAR));

				if (!pObjNameInfo) {
					std::cerr << "Failed to allocate buffer for object name: " << GetLastError() << std::endl;

					CloseHandle(TargetHandle);
					free(pSysHandleInfo);
					pSysHandleInfo = NULL;

					return;
				}

				// Getting the object's name.
				while (pNtQueryObject(TargetHandle,
					(OBJECT_INFORMATION_CLASS)ObjectNameInformation,
					pObjNameInfo,
					ObjectInformationLength,
					&ReturnLength) == STATUS_INFO_LENGTH_MISMATCH) {
					free(pObjNameInfo);
					ObjectInformationLength = ReturnLength;
					pObjNameInfo = (POBJECT_NAME_INFORMATION)calloc(ObjectInformationLength, sizeof(UCHAR));

					if (!pObjNameInfo) {
						std::cerr << "Failed to allocate buffer for object name: " << GetLastError() << std::endl;

						CloseHandle(TargetHandle);
						free(pSysHandleInfo);
						pSysHandleInfo = NULL;

						return;
					}
				}

				// Checking if the object is a socket.
				if ((pObjNameInfo->Name.Length / 2) == wcslen(pcwDeviceAfd)) {
					if ((wcsncmp(pObjNameInfo->Name.Buffer, pcwDeviceAfd, wcslen(pcwDeviceAfd)) == 0)) {
						WsaErr = WSADuplicateSocketW((SOCKET)TargetHandle, GetCurrentProcessId(), &WsaProtocolInfo);

						if (WsaErr != 0) {
							std::cerr << "Failed retrieving WSA protocol info: " << WsaErr << std::endl;

							CloseHandle(TargetHandle);
							free(pObjNameInfo);
							free(pSysHandleInfo);
							pSysHandleInfo = NULL;
							pObjNameInfo = NULL;

							return;
						}
						else {
							TargetSocket = WSASocket(WsaProtocolInfo.iAddressFamily,
								WsaProtocolInfo.iSocketType,
								WsaProtocolInfo.iProtocol,
								&WsaProtocolInfo,
								0,
								WSA_FLAG_OVERLAPPED);

							if (TargetSocket != INVALID_SOCKET) {
								free(pObjNameInfo);
								pObjNameInfo = NULL;

								if (WsaProtocolInfo.iAddressFamily == AF_INET)
									PrintInformation(TargetSocket, pid);
							}
						}
					}
				}
				free(pObjNameInfo);
				pObjNameInfo = NULL;
			}
		}
	}
	CloseHandle(TargetHandle);
	free(pSysHandleInfo);
}

void PrintInformation(SOCKET socket, DWORD pid) {
	sockaddr_in socketAddress;
	int nameLength = sizeof(sockaddr_in);
	int result = getpeername(socket, (PSOCKADDR)&socketAddress, &nameLength);

	if (result == 0) {
		fwprintf(stdout, L"Pid: %d\tAddress: %u.%u.%u.%u\tPort: %hu\n",
			pid,
			socketAddress.sin_addr.S_un.S_un_b.s_b1,
			socketAddress.sin_addr.S_un.S_un_b.s_b2,
			socketAddress.sin_addr.S_un.S_un_b.s_b3,
			socketAddress.sin_addr.S_un.S_un_b.s_b4,
			ntohs(socketAddress.sin_port));
	}

	// I filtered the 10057 error code since it means that the socket is not connected.
	// https://docs.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2
	else {
		int err = WSAGetLastError();
		
		if (err != 10057)
			std::cerr << "Failed to retrieve address of the peer: " << WSAGetLastError() << " for pid " << pid << std::endl;
	}
	closesocket(socket);
}
