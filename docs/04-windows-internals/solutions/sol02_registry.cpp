// Solution 02 — Registry

#include <windows.h>
#include <iostream>
#include <string>

static const char* RUN_KEY = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

bool SetRunKey(const char* valueName, const char* exePath) {
    HKEY hKey;
    LONG res = RegOpenKeyExA(HKEY_CURRENT_USER, RUN_KEY, 0, KEY_SET_VALUE, &hKey);
    if (res != ERROR_SUCCESS) return false;

    res = RegSetValueExA(hKey, valueName, 0, REG_SZ,
                         (const BYTE*)exePath, (DWORD)(strlen(exePath) + 1));
    RegCloseKey(hKey);
    return res == ERROR_SUCCESS;
}

bool DeleteRunKey(const char* valueName) {
    HKEY hKey;
    LONG res = RegOpenKeyExA(HKEY_CURRENT_USER, RUN_KEY, 0, KEY_SET_VALUE, &hKey);
    if (res != ERROR_SUCCESS) return false;

    res = RegDeleteValueA(hKey, valueName);
    RegCloseKey(hKey);
    return res == ERROR_SUCCESS;
}

bool RunKeyExists(const char* valueName) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, RUN_KEY, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return false;
    DWORD type = 0, size = 0;
    LONG res = RegQueryValueExA(hKey, valueName, nullptr, &type, nullptr, &size);
    RegCloseKey(hKey);
    return res == ERROR_SUCCESS;
}

std::string GetRunKeyValue(const char* valueName) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, RUN_KEY, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
        return "";
    DWORD type = REG_SZ, size = 512;
    char buf[512] = {};
    LONG res = RegQueryValueExA(hKey, valueName, nullptr, &type, (LPBYTE)buf, &size);
    RegCloseKey(hKey);
    return res == ERROR_SUCCESS ? std::string(buf) : "";
}

int main() {
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);

    std::cout << "EXE path: " << exePath << "\n";

    std::cout << "SetRunKey: " << (SetRunKey("TestPersistence", exePath) ? "ok" : "FAILED") << "\n";
    std::cout << "Exists: "    << (RunKeyExists("TestPersistence") ? "yes" : "no") << "\n";
    std::cout << "Value: "     << GetRunKeyValue("TestPersistence") << "\n";

    std::cout << "DeleteRunKey: " << (DeleteRunKey("TestPersistence") ? "ok" : "FAILED") << "\n";
    std::cout << "Exists after delete: " << (RunKeyExists("TestPersistence") ? "yes" : "no") << "\n";

    return 0;
}
