#include <iostream>
#include <WinSock2.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <winternl.h>
#include <list>
#include "GetUdpCommunication.h"

std::list<DWORD> GetProcesses();
SOCKET GetSocket(DWORD pid);

int main()
{
	std::list<DWORD> processes = GetProcesses();
	SOCKET processSocket;
	std::list<std::string> remoteAddresses;

	for (DWORD pid : processes) {
		//WSADuplicateSocket(processSocket, pid, NULL);
	}
}

std::list<DWORD> GetProcesses() {
	// Reference: https://github.com/w4kfu/whook/blob/master/src/network.cpp

	std::list<DWORD> lmib;
	PMIB_UDPTABLE_OWNER_PID pmib;
	DWORD dwSize = 0;
	DWORD dwRetVal;

	pmib = (PMIB_UDPTABLE_OWNER_PID)malloc(sizeof(MIB_UDPTABLE_OWNER_PID));
	if (pmib == NULL) {
		OutputDebugStringA("[GetProcesses] malloc failed.");
		return lmib;
	}
	dwSize = sizeof(MIB_UDPTABLE_OWNER_PID);

	if ((dwRetVal = GetExtendedUdpTable(pmib, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0)) == ERROR_INSUFFICIENT_BUFFER) {
		free(pmib);
		pmib = (PMIB_UDPTABLE_OWNER_PID)malloc(dwSize);

		if (pmib == NULL) {
			OutputDebugStringA("[GetProcesses] malloc failed.");
			return lmib;
		}
	}
	dwRetVal = GetExtendedUdpTable(pmib, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);

	if (dwRetVal != 0) {
		OutputDebugStringA("[GetProcesses] GetExtendedUdpTable failed.\n");
		// fprintf(stderr, "[-] GetUDPConnections - GetExtendedUdpTable failed : %lu\n", GetLastError());
		return lmib;
	}
	for (DWORD i = 0; i < pmib->dwNumEntries; i++) {
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
		while (NtQuerySystemInformation(SystemHandleInformation,
			pSystemHandleInformation,
			systemInformationLength,
			&returnLength) == STATUS_INFO_LENGTH_MISMATCH) {

			free(pSystemHandleInformation);
			systemInformationLength = returnLength;
			pSystemHandleInformation = (PSYSTEM_HANDLE_INFORMATION)calloc(systemInformationLength, sizeof(UCHAR));

			if (!pSystemHandleInformation)
				break;
		}

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
			while (NtQueryObject(targetHandle,
				(OBJECT_INFORMATION_CLASS)ObjectNameInformation,
				pObjectNameInformation,
				objectInformationLength,
				&returnLength) == STATUS_INFO_LENGTH_MISMATCH) {

				free(pObjectNameInformation);
				objectInformationLength = returnLength;
				pObjectNameInformation = (POBJECT_NAME_INFORMATION)calloc(objectInformationLength, sizeof(UCHAR));

				if (!pObjectNameInformation)
					break; // NEED TO EXIT COMPLETLY.
			}

			// Checking if the object name matches to the UDP.
			if ((pObjectNameInformation->Name.Length / 2) == wcslen(pcwDeviceUdp)) {

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