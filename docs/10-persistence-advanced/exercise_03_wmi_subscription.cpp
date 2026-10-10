/*
  Exercise 03 — WMI Event Subscription Persistence
  ==================================================
  WMI permanent event subscriptions survive reboots without touching the
  registry run keys or startup folders, making them harder to detect.

  Three objects must be created in root\subscription:
    __EventFilter             — "when does the event fire?" (WQL query)
    CommandLineEventConsumer  — "what do we run?" (command string)
    __FilterToConsumerBinding — links the filter to the consumer

  YOUR TASKS
  ----------
  1. Implement initializeCOM()    — CoInitializeEx + CoInitializeSecurity
  2. Implement connectToWMI()     — IWbemLocator → IWbemServices for root\subscription
  3. Implement createEventFilter() — spawn + populate + PutInstance for __EventFilter
  4. Implement createConsumer()   — spawn + populate + PutInstance for CommandLineEventConsumer
  5. Implement createBinding()    — spawn + populate + PutInstance for __FilterToConsumerBinding

  Compile:
    g++ -std=c++17 -Wall -o ex03.exe exercise_03_wmi_subscription.cpp \
        -lwbemuuid -lole32 -loleaut32

  Cleanup when done (admin shell):
    Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer | Remove-WmiObject
    Get-WMIObject -Namespace root\subscription -Class __EventFilter | Remove-WmiObject
    Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject

  IMPORTANT: Requires Administrator to create WMI subscriptions.
*/

#define _WIN32_DCOM
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <iostream>
#include <string>

// Names used for our demo objects
static const wchar_t* FILTER_NAME   = L"ExerciseFilter";
static const wchar_t* CONSUMER_NAME = L"ExerciseConsumer";
// Query: fires when any new process starts (WITHIN 30 = poll every 30s)
static const wchar_t* FILTER_QUERY  =
    L"SELECT * FROM __InstanceCreationEvent WITHIN 30 "
    L"WHERE TargetInstance ISA 'Win32_Process' "
    L"AND TargetInstance.Name='notepad.exe'";
// Command to run when the event fires
static const wchar_t* CONSUMER_CMD  = L"cmd.exe /c echo triggered >> C:\\Temp\\wmi_hit.txt";

// ─────────────────────────────────────────────────────────────────────────────
// TODO 1 — initializeCOM
//   Call CoInitializeEx(NULL, COINIT_MULTITHREADED).
//   Call CoInitializeSecurity(NULL, -1, NULL, NULL,
//       RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
//       NULL, EOAC_NONE, NULL).
//   Return true on success.
// ─────────────────────────────────────────────────────────────────────────────
bool initializeCOM() {
    // TODO: implement
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// TODO 2 — connectToWMI
//   Create IWbemLocator via CoCreateInstance(CLSID_WbemLocator, ...).
//   Call pLoc->ConnectServer with namespace L"ROOT\\SUBSCRIPTION".
//   Call CoSetProxyBlanket on the returned IWbemServices pointer.
//   Store the result in *ppSvc; release pLoc before returning.
//   Return true on success.
// ─────────────────────────────────────────────────────────────────────────────
bool connectToWMI(IWbemServices** ppSvc) {
    // TODO: CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
    //                        IID_IWbemLocator, (LPVOID*)&pLoc)
    // TODO: pLoc->ConnectServer(SysAllocString(L"ROOT\\SUBSCRIPTION"),
    //                           NULL, NULL, 0, NULL, 0, 0, ppSvc)
    // TODO: CoSetProxyBlanket(*ppSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
    //           RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE)
    (void)ppSvc;
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// TODO 3 — createEventFilter
//   Get class "\" __EventFilter" via pSvc->GetObject.
//   SpawnInstance to create a new object.
//   Put properties: Name, EventNamespace (L"root\\cimv2"), QueryLanguage (L"WQL"), Query.
//   PutInstance the object back.
//   Print the returned object path.
// ─────────────────────────────────────────────────────────────────────────────
bool createEventFilter(IWbemServices* pSvc) {
    // TODO: pSvc->GetObject(SysAllocString(L"__EventFilter"), 0, NULL, &pClass, NULL)
    // TODO: pClass->SpawnInstance(0, &pFilter)
    // TODO: VARIANT v; VariantInit(&v); v.vt = VT_BSTR; v.bstrVal = SysAllocString(FILTER_NAME);
    //       pFilter->Put(L"Name", 0, &v, 0); VariantClear(&v);
    // TODO: repeat for EventNamespace, QueryLanguage, Query
    // TODO: pSvc->PutInstance(pFilter, WBEM_FLAG_CREATE_OR_UPDATE, NULL, &pCallResult)
    (void)pSvc;
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// TODO 4 — createConsumer
//   Same pattern for "CommandLineEventConsumer".
//   Properties: Name = CONSUMER_NAME, CommandLineTemplate = CONSUMER_CMD.
// ─────────────────────────────────────────────────────────────────────────────
bool createConsumer(IWbemServices* pSvc) {
    // TODO: GetObject("CommandLineEventConsumer"), SpawnInstance, Put Name + CommandLineTemplate
    // TODO: PutInstance
    (void)pSvc;
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// TODO 5 — createBinding
//   For "__FilterToConsumerBinding":
//   Filter   property = L"__EventFilter.Name=\"ExerciseFilter\""
//   Consumer property = L"CommandLineEventConsumer.Name=\"ExerciseConsumer\""
//   PutInstance the binding.
// ─────────────────────────────────────────────────────────────────────────────
bool createBinding(IWbemServices* pSvc) {
    // TODO: GetObject("__FilterToConsumerBinding"), SpawnInstance
    // TODO: Put Filter = L"__EventFilter.Name=\"ExerciseFilter\""
    // TODO: Put Consumer = L"CommandLineEventConsumer.Name=\"ExerciseConsumer\""
    // TODO: PutInstance
    (void)pSvc;
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
int main() {
    std::cout << "=== Exercise 03: WMI Event Subscription Persistence ===\n\n";
    std::cout << "NOTE: Requires Administrator privileges.\n\n";

    std::cout << "[1] Initializing COM ...\n";
    if (!initializeCOM()) {
        std::cout << "    Failed (complete TODO 1).\n";
        return 1;
    }
    std::cout << "    OK.\n\n";

    std::cout << "[2] Connecting to root\\subscription ...\n";
    IWbemServices* pSvc = nullptr;
    if (!connectToWMI(&pSvc)) {
        std::cout << "    Failed (complete TODO 2).\n";
        CoUninitialize();
        return 1;
    }
    std::cout << "    Connected.\n\n";

    std::cout << "[3] Creating __EventFilter ...\n";
    if (createEventFilter(pSvc))
        std::cout << "    Created.\n\n";
    else
        std::cout << "    Failed (complete TODO 3).\n\n";

    std::cout << "[4] Creating CommandLineEventConsumer ...\n";
    if (createConsumer(pSvc))
        std::cout << "    Created.\n\n";
    else
        std::cout << "    Failed (complete TODO 4).\n\n";

    std::cout << "[5] Creating __FilterToConsumerBinding ...\n";
    if (createBinding(pSvc))
        std::cout << "    Bound.\n\n";
    else
        std::cout << "    Failed (complete TODO 5).\n\n";

    if (pSvc) pSvc->Release();
    CoUninitialize();

    std::cout << "Persistence subscription registered.\n"
              << "Open notepad.exe to trigger it.\n";
    return 0;
}
