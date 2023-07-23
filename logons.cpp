#include "stuff.h"

template<typename T>
std::wstring to_hex(T value) {
    std::wstringstream wss;
    wss << std::setfill(L'0') << std::setw(sizeof(T) * 2) << std::hex << std::uppercase << static_cast<int64_t>(value);
    return wss.str();
}

void NtCheckError(NTSTATUS status) {
    if (status != 0) {
        DWORD err;
        std::wcout << L"[-] LsaNt Error: " << LsaNtStatusToWinError(status) << std::endl;
        exit(-1);
    }
}

VOID filetimeToTime(const FILETIME* time) {
    SYSTEMTIME st;
    FileTimeToSystemTime(time, &st);
    std::cout << st.wDay << "." << st.wMonth << "." << st.wYear << " " << st.wHour << ":" << st.wMinute << ":" << st.wSecond << std::endl;
}

std::wstring GetUserNameFromLogonId(LUID LogonId)
{
    PSECURITY_LOGON_SESSION_DATA pSessionData = NULL;
    if (LsaGetLogonSessionData(&LogonId, &pSessionData) != 0) {
        return L"";
    }

    std::wstring domainName(pSessionData->LogonDomain.Buffer, pSessionData->LogonDomain.Buffer + wcslen(pSessionData->LogonDomain.Buffer));
    std::wstring userName(pSessionData->UserName.Buffer, pSessionData->UserName.Buffer + wcslen(pSessionData->UserName.Buffer));
    LsaFreeReturnBuffer(pSessionData);

    return domainName + L"\\" + userName;
}

std::map<int, std::string> enumToString = {
  {UndefinedLogonType, "UndefinedLogonType"},
  {Interactive, "Interactive"},
  {Network, "Network"},
  {Batch, "Batch"},
  {Service, "Service"},
  {Proxy, "Proxy"},
  {Unlock, "Unlock"},
  {NetworkCleartext, "NetworkCleartext"},
  {NewCredentials, "NewCredentials"},
  {RemoteInteractive, "RemoteInteractive"},
  {CachedInteractive, "CachedInteractive"},
  {CachedRemoteInteractive, "CachedRemoteInteractive"},
  {CachedUnlock, "CachedUnlock"}
};

BOOL LogonInfo(LUID* LogonSession)
{
    std::vector<LUID> logonIds;
    PLUID sessions;
    ULONG sessionCount;
    if (LsaEnumerateLogonSessions(&sessionCount, &sessions) != 0) {
        return FALSE;
    }

    for (ULONG i = 0; i < sessionCount; ++i) {
        logonIds.push_back(sessions[i]);
    }

    LsaFreeReturnBuffer(sessions);

    for (size_t i = 0; i < logonIds.size(); ++i) {
        std::wcout << L"\t[!] Index: " << i << L", Logon ID: " << to_hex(logonIds[i].LowPart) << ", Username: " << GetUserNameFromLogonId(logonIds[i]) << '\n';

    }

    size_t index;
    std::cout << "\n[?] Enter index of logon session: ";
    std::cin >> index;

    if (index < logonIds.size()) {
        LUID selectedLogonId = logonIds[index];
        *LogonSession = selectedLogonId;
        return TRUE;
    }
    else {
        return FALSE;
    }
    return FALSE;
}