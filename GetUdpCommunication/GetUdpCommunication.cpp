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

	SOCKET processSocket;
	std::list<std::string> remoteAddresses;

	for (DWORD pid : processes) {
		processSocket = GetSocket(pid);
	}
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
	NtDuplicateObject = (NTDUPLICATEOBJECT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDuplicateObject");
	pNtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
	pNtQueryObject = (NTQUERYOBJECT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");

	if (NtDuplicateObject && pNtQuerySystemInformation && pNtQueryObject) {
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
		OutputDebugStringA("[GetProcesses] malloc failed.");
		return lmib;
	}
	dwSize = sizeof(MIB_UDPTABLE_OWNER_PID);

	// See if it is a good size.
	if ((dwRetVal = GetExtendedUdpTable(pmib, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0)) == ERROR_INSUFFICIENT_BUFFER) {
		free(pmib);
		pmib = (PMIB_UDPTABLE_OWNER_PID)malloc(dwSize);

		if (pmib == NULL) {
			OutputDebugStringA("[GetProcesses] malloc failed.");
			return lmib;
		}
	}

	// Filling up the table.
	dwRetVal = GetExtendedUdpTable(pmib, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);

	if (dwRetVal != 0) {
		OutputDebugStringA("[GetProcesses] GetExtendedUdpTable failed.\n");
		// fprintf(stderr, "[-] GetUDPConnections - GetExtendedUdpTable failed : %lu\n", GetLastError());
		return lmib;
	}

	// Removing the duplications.
	for (DWORD i = 0; i < pmib->dwNumEntries; i++) {
		bool add = true;

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

SOCKET GetSocket(DWORD pid) {
	// Reference: https://github.com/0xcpu/winsmsd/blob/master/winsmsd.c

	PSYSTEM_HANDLE_INFORMATION pSystemHandleInformation = NULL;
	POBJECT_NAME_INFORMATION pObjectNameInformation = NULL;
	ULONG systemInformationLength = 0;
	ULONG objectInformationLength = 0;
	ULONG returnLength;
	HANDLE targetHandle = INVALID_HANDLE_VALUE;
	SOCKET targetSocket = INVALID_SOCKET;
	NTSTATUS ntStatus;
	PCWSTR pcwDeviceUdp = L"\\Device\\Udp";
	INT wsaErr;
	WSAPROTOCOL_INFOW wsaProtocolInfo = { 0 };

	// Duplicating the process handle.
	HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);

	if (!VALID_HANDLE(hProcess)) {
		OutputDebugStringA("[GetSocket] Could not open process.");
		return targetSocket;
	}

	do {
		pSystemHandleInformation = (PSYSTEM_HANDLE_INFORMATION)calloc(systemInformationLength, sizeof(UCHAR));

		if (!pSystemHandleInformation)
			break;

		// Filling the system handle information (handle tables).
		while (pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation,
			pSystemHandleInformation,
			systemInformationLength,
			&returnLength) == STATUS_INFO_LENGTH_MISMATCH) {

			free(pSystemHandleInformation);
			systemInformationLength = returnLength;
			pSystemHandleInformation = (PSYSTEM_HANDLE_INFORMATION)calloc(systemInformationLength, sizeof(UCHAR));

			if (!pSystemHandleInformation)
				break;
		}

		if (!pSystemHandleInformation)
			break;

		// Iterating the handles.
		for (size_t i = 0; i < pSystemHandleInformation->NumberOfHandles; i++) {

			// Getting the object's handle.
			ntStatus = NtDuplicateObject(hProcess,
				(HANDLE)pSystemHandleInformation->Handles[i].HandleValue,
				GetCurrentProcess(),
				&targetHandle,
				PROCESS_ALL_ACCESS,
				FALSE,
				DUPLICATE_SAME_ACCESS);

			if (ntStatus != STATUS_SUCCESS)
				break;

			pObjectNameInformation = (POBJECT_NAME_INFORMATION)calloc(objectInformationLength, sizeof(UCHAR));

			if (!pObjectNameInformation)
				break;

			// Getting the object's name.
			while (pNtQueryObject(targetHandle,
				(OBJECT_INFORMATION_CLASS)ObjectNameInformation,
				pObjectNameInformation,
				objectInformationLength,
				&returnLength) == STATUS_INFO_LENGTH_MISMATCH) {

				free(pObjectNameInformation);
				objectInformationLength = returnLength;
				pObjectNameInformation = (POBJECT_NAME_INFORMATION)calloc(objectInformationLength, sizeof(UCHAR));

				if (!pObjectNameInformation)
					break;
			}

			if (!pObjectNameInformation)
				break;

			// Checking if the object name matches to the UDP.
			if ((pObjectNameInformation->Name.Length / 2) == wcslen(pcwDeviceUdp)) {
				if ((wcsncmp(pObjectNameInformation->Name.Buffer, pcwDeviceUdp, wcslen(pcwDeviceUdp)) == 0)) {

					// Trying to duplicate the socket handle.
					wsaErr = WSADuplicateSocketW((SOCKET)targetHandle, GetCurrentProcessId(), &wsaProtocolInfo);

					if (wsaErr != 0) {
						OutputDebugStringA("Failed to retrieve WSA protocol info.");
						break;
					}

					targetSocket = WSASocket(wsaProtocolInfo.iAddressFamily,
						wsaProtocolInfo.iSocketType,
						wsaProtocolInfo.iProtocol,
						&wsaProtocolInfo,
						0,
						WSA_FLAG_OVERLAPPED);

					if (targetSocket != INVALID_SOCKET) {
						std::cout << "Socket was duplicated!" << std::endl;
						// fwprintf(stdout, L"[OK] Socket was duplicated!\n");
						break;
					}
					else {
						std::cout << "Failed to duplicate socket: " << GetLastError() << std::endl;
						break;
					}
				}
			}
		}
	} while (false);

	// Cleanup.
	if (pObjectNameInformation)
		free(pObjectNameInformation);
	if (pSystemHandleInformation)
		free(pSystemHandleInformation);
	if (targetHandle)
		CloseHandle(targetHandle);
	CloseHandle(hProcess);
	return targetSocket;
}