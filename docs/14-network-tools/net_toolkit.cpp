// net_toolkit.cpp — Complete Network Toolkit (standalone, ~400 lines)
//
// Usage:
//   net_toolkit.exe scan <host> <port_range>   e.g. scan 192.168.1.1 1-1024
//   net_toolkit.exe dns <hostname>             full DNS lookup
//   net_toolkit.exe inventory                  local network inventory
//   net_toolkit.exe serve <port>               HTTP server serving CWD
//   net_toolkit.exe grab <host> <port>         raw TCP banner grab
//
// Compile:
//   g++ -std=c++17 -Wall -o net_toolkit.exe net_toolkit.cpp -lws2_32 -liphlpapi -ldnsapi

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <windns.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>
#include <unordered_set>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "dnsapi.lib")

// ============================================================
// Shared helpers
// ============================================================
static std::string ip4_str(DWORD le)
{
    char b[INET_ADDRSTRLEN]; struct in_addr a; a.s_addr=le;
    inet_ntop(AF_INET,&a,b,sizeof(b)); return b;
}
static std::string mac_str(const BYTE* m, DWORD l)
{
    if(!l) return "(none)";
    char b[32]={};
    for(DWORD i=0;i<l&&i<6;i++){if(i)strcat_s(b,":");char h[4];snprintf(h,4,"%02X",m[i]);strcat_s(b,h);}
    return b;
}
static std::string proc_name(DWORD pid)
{
    if(!pid) return "System";
    HANDLE s=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(s==INVALID_HANDLE_VALUE) return "?";
    PROCESSENTRY32 pe={sizeof(pe)}; std::string n="?";
    if(Process32First(s,&pe)) do{ if(pe.th32ProcessID==pid){n=pe.szExeFile;break;} }while(Process32Next(s,&pe));
    CloseHandle(s); return n;
}
static std::string http_date_now()
{
    time_t now=time(NULL); struct tm t; gmtime_s(&t,&now);
    char b[64]; strftime(b,sizeof(b),"%a, %d %b %Y %H:%M:%S GMT",&t); return b;
}

// ============================================================
// COMMAND: scan
// ============================================================
static void cmd_scan(const char* host, int lo, int hi)
{
    printf("Scanning %s ports %d-%d (500ms timeout)...\n\n", host, lo, hi);

    struct addrinfo hints={},*res=NULL;
    hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,NULL,&hints,&res)!=0){
        fprintf(stderr,"Cannot resolve %s\n",host); return;
    }
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&((struct sockaddr_in*)res->ai_addr)->sin_addr,ip,sizeof(ip));
    freeaddrinfo(res);
    printf("Resolved: %s\n\n", ip);

    int open_count=0;
    for(int port=lo; port<=hi; port++){
        SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        if(s==INVALID_SOCKET) continue;

        // Non-blocking connect with timeout
        u_long mode=1; ioctlsocket(s,FIONBIO,&mode);
        struct sockaddr_in sa={}; sa.sin_family=AF_INET; sa.sin_port=htons((u_short)port);
        inet_pton(AF_INET,ip,&sa.sin_addr);
        connect(s,(struct sockaddr*)&sa,sizeof(sa));

        fd_set wfds; FD_ZERO(&wfds); FD_SET(s,&wfds);
        struct timeval tv={0,500000}; // 500ms
        int rc=select(0,NULL,&wfds,NULL,&tv);
        if(rc>0){
            // Check for error (connection refused sets error)
            int err=0; int elen=sizeof(err);
            getsockopt(s,SOL_SOCKET,SO_ERROR,(char*)&err,&elen);
            if(err==0){
                printf("  %-6d open\n", port);
                open_count++;
            }
        }
        closesocket(s);
    }
    printf("\n%d open ports found.\n", open_count);
}

// ============================================================
// COMMAND: dns
// ============================================================
static void cmd_dns(const char* host)
{
    printf("=== DNS Lookup: %s ===\n\n", host);

    // A / AAAA
    printf("[A/AAAA]\n");
    struct addrinfo hints={},*r=NULL;
    hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    if(getaddrinfo(host,NULL,&hints,&r)==0){
        for(struct addrinfo* ai=r;ai;ai=ai->ai_next){
            char ip[INET6_ADDRSTRLEN]={};
            if(ai->ai_family==AF_INET)
                inet_ntop(AF_INET,&((struct sockaddr_in*)ai->ai_addr)->sin_addr,ip,sizeof(ip));
            else
                inet_ntop(AF_INET6,&((struct sockaddr_in6*)ai->ai_addr)->sin6_addr,ip,sizeof(ip));
            printf("  %s  %s\n", ai->ai_family==AF_INET?"A    ":"AAAA ", ip);
        }
        freeaddrinfo(r);
    } else { printf("  (no results)\n"); }

    // MX
    printf("\n[MX]\n");
    PDNS_RECORD rec=NULL;
    if(DnsQuery_A(host,DNS_TYPE_MX,DNS_QUERY_STANDARD,NULL,&rec,NULL)==ERROR_SUCCESS){
        for(PDNS_RECORD p=rec;p;p=p->pNext)
            if(p->wType==DNS_TYPE_MX)
                printf("  priority=%-5u  %s\n",p->Data.MX.wPreference,p->Data.MX.pNameExchange);
        DnsRecordListFree(rec,DnsFreeRecordList);
    } else { printf("  (none)\n"); }

    // TXT
    printf("\n[TXT]\n");
    if(DnsQuery_A(host,DNS_TYPE_TEXT,DNS_QUERY_STANDARD,NULL,&rec,NULL)==ERROR_SUCCESS){
        for(PDNS_RECORD p=rec;p;p=p->pNext)
            if(p->wType==DNS_TYPE_TEXT)
                for(DWORD i=0;i<p->Data.TXT.dwStringCount;i++)
                    printf("  \"%s\"\n",p->Data.TXT.pStringArray[i]);
        DnsRecordListFree(rec,DnsFreeRecordList);
    } else { printf("  (none)\n"); }

    // CNAME
    printf("\n[CNAME]\n");
    if(DnsQuery_A(host,DNS_TYPE_CNAME,DNS_QUERY_STANDARD,NULL,&rec,NULL)==ERROR_SUCCESS){
        for(PDNS_RECORD p=rec;p;p=p->pNext)
            if(p->wType==DNS_TYPE_CNAME)
                printf("  %s\n",p->Data.CNAME.pNameHost);
        DnsRecordListFree(rec,DnsFreeRecordList);
    } else { printf("  (none)\n"); }
}

// ============================================================
// COMMAND: inventory
// ============================================================
static void cmd_inventory()
{
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
    printf("=== Network Inventory ===\n");

    // Adapters
    printf("\n[Adapters]\n");
    ULONG bufsz=15000; std::vector<char> buf(bufsz);
    DWORD rc=GetAdaptersAddresses(AF_UNSPEC,GAA_FLAG_INCLUDE_PREFIX,NULL,
        (PIP_ADAPTER_ADDRESSES)buf.data(),&bufsz);
    if(rc==ERROR_BUFFER_OVERFLOW){ buf.resize(bufsz);
        GetAdaptersAddresses(AF_UNSPEC,GAA_FLAG_INCLUDE_PREFIX,NULL,
            (PIP_ADAPTER_ADDRESSES)buf.data(),&bufsz); }
    for(PIP_ADAPTER_ADDRESSES aa=(PIP_ADAPTER_ADDRESSES)buf.data();aa;aa=aa->Next){
        char fn[256]={}; WideCharToMultiByte(CP_UTF8,0,aa->FriendlyName,-1,fn,sizeof(fn),NULL,NULL);
        printf("  %s  MAC=%s  MTU=%lu\n",fn,mac_str(aa->PhysicalAddress,aa->PhysicalAddressLength).c_str(),aa->Mtu);
        for(PIP_ADAPTER_UNICAST_ADDRESS ua=aa->FirstUnicastAddress;ua;ua=ua->Next){
            char ip[INET6_ADDRSTRLEN]={};
            getnameinfo(ua->Address.lpSockaddr,ua->Address.iSockaddrLength,ip,sizeof(ip),NULL,0,NI_NUMERICHOST);
            printf("    %s  %s\n",ua->Address.lpSockaddr->sa_family==AF_INET?"IPv4":"IPv6",ip);
        }
    }

    // ARP
    printf("\n[ARP Table]\n");
    ULONG arpsz=0; GetIpNetTable(NULL,&arpsz,FALSE);
    std::vector<char> arpbuf(arpsz); PMIB_IPNETTABLE arpt=(PMIB_IPNETTABLE)arpbuf.data();
    if(GetIpNetTable(arpt,&arpsz,TRUE)==NO_ERROR)
        for(DWORD i=0;i<arpt->dwNumEntries;i++){
            const char* t=arpt->table[i].dwType==MIB_IPNET_TYPE_DYNAMIC?"dyn":"static";
            printf("  %-18s  %s  %s\n",
                ip4_str(arpt->table[i].dwAddr).c_str(),
                mac_str(arpt->table[i].bPhysAddr,arpt->table[i].dwPhysAddrLen).c_str(),t);
        }

    // Routes
    printf("\n[Routing Table]\n");
    printf("  %-18s %-18s %-18s  If   Metric\n","Destination","Mask","Gateway");
    ULONG rtsz=0; GetIpForwardTable(NULL,&rtsz,FALSE);
    std::vector<char> rtbuf(rtsz); PMIB_IPFORWARDTABLE rtt=(PMIB_IPFORWARDTABLE)rtbuf.data();
    if(GetIpForwardTable(rtt,&rtsz,TRUE)==NO_ERROR)
        for(DWORD i=0;i<rtt->dwNumEntries;i++)
            printf("  %-18s %-18s %-18s  %-4lu  %lu\n",
                ip4_str(rtt->table[i].dwForwardDest).c_str(),
                ip4_str(rtt->table[i].dwForwardMask).c_str(),
                ip4_str(rtt->table[i].dwForwardNextHop).c_str(),
                rtt->table[i].dwForwardIfIndex,rtt->table[i].dwForwardMetric1);

    // Connections
    printf("\n[Active Connections]\n");
    printf("  %-6s %-22s %-22s %-13s  PID    Process\n","Proto","Local","Remote","State");
    static const char* ST[]={"","CLOSED","LISTEN","SYN_SENT","SYN_RCVD","ESTABLISHED",
        "FIN_WAIT1","FIN_WAIT2","CLOSE_WAIT","CLOSING","LAST_ACK","TIME_WAIT","DELETE"};
    ULONG tsz=0; GetExtendedTcpTable(NULL,&tsz,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
    std::vector<char> tbuf(tsz); PMIB_TCPTABLE_OWNER_PID tt=(PMIB_TCPTABLE_OWNER_PID)tbuf.data();
    if(GetExtendedTcpTable(tt,&tsz,TRUE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)==NO_ERROR)
        for(DWORD i=0;i<tt->dwNumEntries;i++){
            char la[22],ra[22];
            struct in_addr a; a.s_addr=tt->table[i].dwLocalAddr; char lip[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&a,lip,sizeof(lip));
            a.s_addr=tt->table[i].dwRemoteAddr; char rip[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&a,rip,sizeof(rip));
            snprintf(la,sizeof(la),"%s:%u",lip,ntohs((u_short)tt->table[i].dwLocalPort));
            snprintf(ra,sizeof(ra),"%s:%u",rip,ntohs((u_short)tt->table[i].dwRemotePort));
            DWORD st=tt->table[i].dwState; const char* s=(st>=1&&st<=12)?ST[st]:"?";
            printf("  %-6s %-22s %-22s %-13s  %-6lu  %s\n",
                "TCP",la,ra,s,tt->table[i].dwOwningPid,proc_name(tt->table[i].dwOwningPid).c_str());
        }
    ULONG usz=0; GetExtendedUdpTable(NULL,&usz,FALSE,AF_INET,UDP_TABLE_OWNER_PID,0);
    std::vector<char> ubuf(usz); PMIB_UDPTABLE_OWNER_PID ut=(PMIB_UDPTABLE_OWNER_PID)ubuf.data();
    if(GetExtendedUdpTable(ut,&usz,TRUE,AF_INET,UDP_TABLE_OWNER_PID,0)==NO_ERROR)
        for(DWORD i=0;i<ut->dwNumEntries;i++){
            char la[22]; struct in_addr a; a.s_addr=ut->table[i].dwLocalAddr;
            char lip[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&a,lip,sizeof(lip));
            snprintf(la,sizeof(la),"%s:%u",lip,ntohs((u_short)ut->table[i].dwLocalPort));
            printf("  %-6s %-22s %-22s %-13s  %-6lu  %s\n",
                "UDP",la,"*:*","LISTEN",ut->table[i].dwOwningPid,proc_name(ut->table[i].dwOwningPid).c_str());
        }
    WSACleanup();
}

// ============================================================
// COMMAND: serve
// ============================================================
static volatile bool g_serve_run=true;
static BOOL WINAPI ctrl_h(DWORD t){ if(t==CTRL_C_EVENT){g_serve_run=false;return TRUE;} return FALSE; }

static void serve_file(SOCKET c, const std::string& path_str)
{
    // Read file
    FILE* f=fopen(path_str.c_str(),"rb");
    std::string body,ctype="application/octet-stream";
    if(f){
        fseek(f,0,SEEK_END); long sz=ftell(f); rewind(f);
        if(sz>0&&sz<10*1024*1024){ body.resize(sz); fread(&body[0],1,sz,f); }
        fclose(f);
        if(path_str.find(".html")!=std::string::npos) ctype="text/html; charset=utf-8";
        else if(path_str.find(".txt")!=std::string::npos) ctype="text/plain";
        else if(path_str.find(".js")!=std::string::npos) ctype="application/javascript";
        else if(path_str.find(".css")!=std::string::npos) ctype="text/css";
    }
    int code=body.empty()?404:200; const char* msg=body.empty()?"Not Found":"OK";
    if(body.empty()) body="404 Not Found\r\n";
    std::ostringstream r;
    r<<"HTTP/1.1 "<<code<<" "<<msg<<"\r\n"
     <<"Date: "<<http_date_now()<<"\r\n"
     <<"Content-Type: "<<ctype<<"\r\n"
     <<"Content-Length: "<<body.size()<<"\r\n"
     <<"Connection: close\r\n\r\n"<<body;
    std::string resp=r.str();
    send(c,resp.c_str(),(int)resp.size(),0);
}

static void cmd_serve(int port)
{
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
    SetConsoleCtrlHandler(ctrl_h,TRUE);
    SOCKET srv=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    int opt=1; setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,(char*)&opt,sizeof(opt));
    struct sockaddr_in sa={}; sa.sin_family=AF_INET; sa.sin_addr.s_addr=INADDR_ANY; sa.sin_port=htons((u_short)port);
    if(bind(srv,(struct sockaddr*)&sa,sizeof(sa))==SOCKET_ERROR){
        fprintf(stderr,"bind failed: %d\n",WSAGetLastError()); return;
    }
    listen(srv,SOMAXCONN);
    printf("Serving current directory on http://0.0.0.0:%d\nCtrl+C to stop.\n\n",port);
    DWORD to=1000; setsockopt(srv,SOL_SOCKET,SO_RCVTIMEO,(char*)&to,sizeof(to));

    while(g_serve_run){
        struct sockaddr_in ca={}; int cl=sizeof(ca);
        SOCKET conn=accept(srv,(struct sockaddr*)&ca,&cl);
        if(conn==INVALID_SOCKET){int e=WSAGetLastError();if(e==WSAETIMEDOUT||e==WSAEWOULDBLOCK)continue;break;}
        char rbuf[4096]={}; recv(conn,rbuf,(int)sizeof(rbuf)-1,0);
        // Parse path
        char method[16]={},path[512]={};
        sscanf_s(rbuf,"%15s %511s",method,(unsigned)sizeof(method),path,(unsigned)sizeof(path));
        // Sanitize path: strip leading / and any ..
        std::string fpath=path; if(!fpath.empty()&&fpath[0]=='/') fpath.erase(0,1);
        if(fpath.empty()) fpath="index.html";
        // Reject path traversal
        if(fpath.find("..")!=std::string::npos){ fpath=""; }
        char cwd[MAX_PATH]={}; GetCurrentDirectoryA(MAX_PATH,cwd);
        std::string full=std::string(cwd)+"\\"+fpath;
        for(char& c:full) if(c=='/') c='\\';
        char rip[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&ca.sin_addr,rip,sizeof(rip));
        time_t now=time(NULL); struct tm t; localtime_s(&t,&now);
        char ts[16]; strftime(ts,sizeof(ts),"%H:%M:%S",&t);
        printf("[%s] %s \"%s %s\"\n",ts,rip,method,path);
        serve_file(conn,full);
        closesocket(conn);
    }
    closesocket(srv); WSACleanup();
    printf("Server stopped.\n");
}

// ============================================================
// COMMAND: grab
// ============================================================
static void cmd_grab(const char* host, int port)
{
    printf("Banner grab: %s:%d\n\n", host, port);
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);

    struct addrinfo hints={},*res=NULL;
    hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
    char portstr[16]; snprintf(portstr,sizeof(portstr),"%d",port);
    if(getaddrinfo(host,portstr,&hints,&res)!=0){
        fprintf(stderr,"Cannot resolve %s\n",host); WSACleanup(); return;
    }
    SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(connect(s,res->ai_addr,(int)res->ai_addrlen)==SOCKET_ERROR){
        fprintf(stderr,"Connect failed: %d\n",WSAGetLastError());
        closesocket(s); freeaddrinfo(res); WSACleanup(); return;
    }
    freeaddrinfo(res);
    printf("Connected. Waiting for banner (5s)...\n");
    DWORD to=5000; setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(char*)&to,sizeof(to));
    char buf[513]={}; int n=recv(s,buf,512,0);
    if(n>0){
        buf[n]='\0';
        printf("Banner (%d bytes):\n%s\n",n,buf);
    } else {
        printf("No banner received (timeout or empty).\n");
    }
    closesocket(s); WSACleanup();
}

// ============================================================
// Entry
// ============================================================
static void usage(const char* p)
{
    printf("Usage:\n");
    printf("  %s scan <host> <lo-hi>     e.g. scan 127.0.0.1 1-1024\n",p);
    printf("  %s dns <hostname>           DNS lookup (A/AAAA/MX/TXT/CNAME)\n",p);
    printf("  %s inventory                local adapters/ARP/routes/connections\n",p);
    printf("  %s serve <port>             HTTP server for current directory\n",p);
    printf("  %s grab <host> <port>       TCP banner grab\n",p);
}

int main(int argc, char* argv[])
{
    if(argc<2){ usage(argv[0]); return 1; }
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);

    const char* cmd=argv[1];
    if(strcmp(cmd,"scan")==0){
        if(argc<4){ fprintf(stderr,"scan needs <host> <lo-hi>\n"); return 1; }
        int lo=1,hi=1024;
        const char* range=argv[3];
        const char* dash=strchr(range,'-');
        if(dash){ lo=atoi(range); hi=atoi(dash+1); }
        else { lo=hi=atoi(range); }
        cmd_scan(argv[2],lo,hi);
    } else if(strcmp(cmd,"dns")==0){
        if(argc<3){ fprintf(stderr,"dns needs <hostname>\n"); return 1; }
        cmd_dns(argv[2]);
    } else if(strcmp(cmd,"inventory")==0){
        WSACleanup(); cmd_inventory(); return 0;
    } else if(strcmp(cmd,"serve")==0){
        if(argc<3){ fprintf(stderr,"serve needs <port>\n"); return 1; }
        WSACleanup(); cmd_serve(atoi(argv[2])); return 0;
    } else if(strcmp(cmd,"grab")==0){
        if(argc<4){ fprintf(stderr,"grab needs <host> <port>\n"); return 1; }
        WSACleanup(); cmd_grab(argv[2],atoi(argv[3])); return 0;
    } else {
        fprintf(stderr,"Unknown command: %s\n\n",cmd);
        usage(argv[0]); return 1;
    }
    WSACleanup();
    return 0;
}
