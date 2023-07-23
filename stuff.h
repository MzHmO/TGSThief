#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <NTSecAPI.h>
#include <map>
#include <regex>
#include <iomanip>
#include <sstream>
#include <vector>
#include <sddl.h>
#include <locale>

#pragma comment(lib, "Secur32.lib")
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)   
#define SECURITY_WIN32

DWORD ImpersonateSystem();
BOOL LogonInfo(LUID* LogonSession);

BOOL AskTgs(HANDLE hLsa, ULONG AP, LUID logonId, LPCWSTR spn, LUID originalLuid);

template<typename T>
std::wstring to_hex(T value);
