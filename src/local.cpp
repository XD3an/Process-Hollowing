#include <iostream>
#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);

    OSVERSIONINFOEX osVersionInfo;
    osVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx(reinterpret_cast<OSVERSIONINFO*>(&osVersionInfo));

    char message[256];
    int count = snprintf(message, sizeof(message), "Computer Name: %s\nOperating System Version: %u.%u", computerName, osVersionInfo.dwMajorVersion, osVersionInfo.dwMinorVersion);
    if (count >= sizeof(message))
    {
        MessageBoxA(NULL, "Message too long!", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    MessageBoxA(NULL, message, "System Information", MB_OK | MB_ICONINFORMATION);

    return 0;
}
