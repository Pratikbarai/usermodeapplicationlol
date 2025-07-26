#include "krabs/krabs.hpp"
#include "resource.h" // For our native dialog
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <thread>
#include <mutex>
#include <fstream>
#include <chrono>
#include <ctime>
#include <sstream>
#include <future>
#include <condition_variable>
#include <queue>
#include <atomic>
#include <functional>
#include <psapi.h>
#include <wincrypt.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "crypt32.lib")

constexpr int MAX_OTP_ATTEMPTS = 3;
const int OTP_TIMEOUT_SEC = 120; // 2 minutes

std::mutex logMutex;
const std::string LOG_ALL = "log_all.txt";
const std::string LOG_MAL = "log_otp_correct_malicious.txt";
const std::string LOG_INVAL = "log_otp_incorrect.txt";
class ThreadPool {
public:
    ThreadPool(size_t numThreads) : stop(false) {
        for (size_t i = 0; i < numThreads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queueMutex);
                        condition.wait(lock, [this] {
                            return stop || !tasks.empty();
                            });
                        if (stop && tasks.empty()) return;
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                }
                });
        }
    }

    template<class F>
    void enqueue(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread& worker : workers) {
            worker.join();
        }
    }

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queueMutex;
    std::condition_variable condition;
    bool stop;
};

// Global thread pool (initialize in main)
ThreadPool* g_threadPool = nullptr;
// Forward declarations for helper functions
void logEvent(const std::string& filename, const std::string& entry);
void suspendProcess(DWORD pid);
void terminateProcess(DWORD pid);
bool is_hollowed_process(DWORD pid);
// Memory operation callback
void memory_event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    if (schema.event_id() == 10) { // VirtualAllocEx
        krabs::parser parser(schema);
        DWORD pid = parser.parse<DWORD>(L"ProcessID");
        SIZE_T size = parser.parse<SIZE_T>(L"Size");
        DWORD prot = parser.parse<DWORD>(L"Protection");
        if (prot & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
            std::wstring alert = L"EXECUTABLE MEMORY ALLOCATION in PID: " +
                std::to_wstring(pid) + L" Size: " +
                std::to_wstring(size);
            logEvent(LOG_MAL, std::string(alert.begin(), alert.end()));
            suspendProcess(pid);
        }
    }
}
void dll_load_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    krabs::parser parser(schema);
    std::wstring dllName = parser.parse<std::wstring>(L"ImageName");
    DWORD pid = parser.parse<DWORD>(L"ProcessID");

    // Check for Meterpreter patterns
    if (dllName.find(L"ReflectiveLoader") != std::wstring::npos ||
        dllName.find(L"metsrv.dll") != std::wstring::npos) {
        std::wstring alert = L"Suspicious DLL loaded: " + dllName +
            L" in PID: " + std::to_wstring(pid);
        logEvent(LOG_MAL, std::string(alert.begin(), alert.end()));
        terminateProcess(pid);
    }
}

// ======== Powershell InputBox GUI for OTP ========
std::wstring PromptForOtpBox(const std::wstring& prompt) {
    std::wstring cmd = L"powershell.exe -NoProfile -Command \"Add-Type -AssemblyName Microsoft.VisualBasic;"
        L"$v=[Microsoft.VisualBasic.Interaction]::InputBox('"
        + prompt + L"','OTP Required',''); Write-Host $v\"";
    FILE* pipe = _wpopen(cmd.c_str(), L"r");
    if (!pipe) return L"";
    wchar_t buf[128] = { 0 };
    std::wstring result;
    if (fgetws(buf, 128, pipe)) result = buf;
    _pclose(pipe);
    while (!result.empty() && (result.back() == L'\n' || result.back() == L'\r' || result.back() == L' '))
        result.pop_back();
    return result;
}
std::wstring base64_decode(const std::wstring& encoded) {
    DWORD requiredLen = 0;
    if (!CryptStringToBinaryW(encoded.c_str(), 0, CRYPT_STRING_BASE64, NULL, &requiredLen, NULL, NULL))
        return L"";
    std::vector<BYTE> buffer(requiredLen);
    if (!CryptStringToBinaryW(encoded.c_str(), 0, CRYPT_STRING_BASE64, buffer.data(), &requiredLen, NULL, NULL))
        return L"";
    return std::wstring((wchar_t*)buffer.data(), requiredLen / sizeof(wchar_t));
}
std::wstring deobfuscate_powershell(const std::wstring& cmd) {
    std::wstring deobf = cmd;
    // Remove escape characters
    size_t pos = 0;
    while ((pos = deobf.find(L"`", pos)) != std::wstring::npos) {
        deobf.erase(pos, 1);
    }
    // Decode base64
    size_t encPos = std::wstring::npos;
    if ((encPos = deobf.find(L"-e ")) != std::wstring::npos || (encPos = deobf.find(L"-enc ")) != std::wstring::npos) {
        size_t start = deobf.find_first_not_of(L" ", encPos + 3);
        if (start != std::wstring::npos) {
            size_t end = deobf.find_first_of(L" ", start);
            std::wstring b64 = (end == std::wstring::npos) ? deobf.substr(start) : deobf.substr(start, end - start);
            std::wstring decoded = base64_decode(b64);
            if (!decoded.empty())
                deobf += L" [DECODED: " + decoded + L"]";
        }
    }
    // Concatenate split strings
    pos = 0;
    while ((pos = deobf.find(L"'", pos)) != std::wstring::npos) {
        size_t end = deobf.find(L"'", pos + 1);
        if (end != std::wstring::npos) {
            deobf.erase(pos, 1);
            deobf.erase(end - 1, 1);
        }
    }
    return deobf;
}

// ======= Timeout-enabled OTP InputBox =======
std::wstring PromptForOtpBoxWithTimeout(const std::wstring& prompt, int timeout_seconds) {
    std::promise<std::wstring> promise;
    auto future = promise.get_future();

    std::thread([prompt, &promise]() {
        std::wstring otp = PromptForOtpBox(prompt);
        promise.set_value(otp);
        }).detach();

    if (future.wait_for(std::chrono::seconds(timeout_seconds)) == std::future_status::ready) {
        return future.get();
    }
    else {
        return L"";
    }
}

// ======== OTP Verifier: Mode + OTP ========
int callOtpVerifier(const std::string& mode, const std::wstring& otp) {
    std::wstring command = L"otpverify.exe " + std::wstring(mode.begin(), mode.end()) + L" " + otp;
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    wchar_t cmdline[512];
    wcsncpy_s(cmdline, command.c_str(), _TRUNCATE);
    BOOL procOK = CreateProcessW(
        NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi
    );
    int exitCode = -1;
    if (procOK) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD code = 1;
        GetExitCodeProcess(pi.hProcess, &code);
        exitCode = (int)code;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    return exitCode;
}

// ======== Logging (thread safe) ========
void logEvent(const std::string& filename, const std::string& entry) {
    std::lock_guard<std::mutex> lock(logMutex);
    std::ofstream log(filename, std::ios::app);
    if (log) {
        auto now = std::chrono::system_clock::now();
        std::time_t cnow = std::chrono::system_clock::to_time_t(now);
        std::tm tmnow;
#ifdef _WIN32
        localtime_s(&tmnow, &cnow);
#else
        tmnow = *std::localtime(&cnow);
#endif
        char buf[32];
        std::strftime(buf, sizeof(buf), "[%Y-%m-%d %H:%M:%S] ", &tmnow);
        log << buf << entry << "\n";
        log.flush();
    }
}

// ======== Mark of the Web =========
bool hasMarkOfTheWeb(const std::wstring& filePath) {
    std::wstring motwPath = filePath + L":Zone.Identifier";
    std::wifstream ads(motwPath);
    if (!ads.is_open()) return false;
    std::wstring line;
    while (std::getline(ads, line))
        if (line.find(L"ZoneId=3") != std::wstring::npos) return true;
    return false;
}

// ======== Parent Process Name (for remote shell detection) ========
std::wstring getParentProcessName(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
    std::wstring result;
    if (Process32First(snap, &entry)) {
        do {
            if (entry.th32ProcessID == pid) {
                DWORD ppid = entry.th32ParentProcessID;
                PROCESSENTRY32 pe2 = { sizeof(PROCESSENTRY32) };
                HANDLE snap2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (Process32First(snap2, &pe2)) {
                    do {
                        if (pe2.th32ProcessID == ppid) {
                            result = pe2.szExeFile;
                            break;
                        }
                    } while (Process32Next(snap2, &pe2));
                }
                CloseHandle(snap2);
                break;
            }
        } while (Process32Next(snap, &entry));
    }
    CloseHandle(snap);
    return result;
}

// ======== Require Two Distinct OTPs For Admin Escalation (Timeout) ========
bool requireTwoDifferentOtps(const std::wstring& baseFileName, const std::wstring& fullPath, DWORD pid)
{
    int maxAttempts = 2;
    std::wstring otp1, otp2;

    // First OTP
    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        std::wostringstream oss;
        oss << L"Enter ADMIN OTP for " << baseFileName
            << L"\nPath: " << fullPath << L"\nPID: " << pid
            << L"\n[First OTP, Attempt " << attempt << L"/" << maxAttempts << L"]:";
        otp1 = PromptForOtpBoxWithTimeout(oss.str(), OTP_TIMEOUT_SEC);

        if (otp1.empty()) {
            MessageBoxW(NULL, L"OTP input timed out.", L"OTP Input", MB_ICONERROR | MB_OK);
            logEvent(LOG_ALL, "First admin OTP prompt timed out.");
            return false;
        }
        if (otp1.length() != 9) {
            MessageBoxW(NULL, L"Invalid OTP!", L"OTP Input", MB_ICONERROR | MB_OK);
            --attempt;
            continue;
        }
        int res1 = callOtpVerifier("admin1", otp1);
        if (res1 == 0) {
            logEvent(LOG_ALL, "First admin OTP correct for escalation.");
            break;
        }
        else {
            logEvent(LOG_INVAL, "First admin OTP invalid for escalation.");
            if (attempt < maxAttempts)
                MessageBoxW(NULL, L"Invalid OTP! Try again.", L"OTP Input", MB_ICONERROR | MB_OK);
        }
        if (attempt == maxAttempts) {
            MessageBoxW(NULL, L"OTP verification failed.", L"OTP Input", MB_ICONERROR | MB_OK);
            return false;
        }
    }

    // Second OTP
    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        std::wostringstream oss;
        oss << L"Enter ADMIN OTP for " << baseFileName
            << L"\nPath: " << fullPath << L"\nPID: " << pid
            << L"\n[Second OTP, Attempt " << attempt << L"/" << maxAttempts << L"]: (Different from first)";
        otp2 = PromptForOtpBoxWithTimeout(oss.str(), OTP_TIMEOUT_SEC);

        if (otp2.empty()) {
            MessageBoxW(NULL, L"OTP input timed out.", L"OTP Input", MB_ICONERROR | MB_OK);
            logEvent(LOG_ALL, "Second admin OTP prompt timed out.");
            return false;
        }
        if (otp2.length() != 9) {
            MessageBoxW(NULL, L"Invalid OTP!", L"OTP Input", MB_ICONERROR | MB_OK);
            --attempt;
            continue;
        }
        if (otp2 == otp1) {
            MessageBoxW(NULL, L"Second OTP must be different from first OTP!", L"OTP Input", MB_ICONERROR | MB_OK);
            --attempt;
            continue;
        }
        int res2 = callOtpVerifier("admin2", otp2);
        if (res2 == 0) {
            logEvent(LOG_ALL, "Second admin OTP correct for escalation.");
            return true;
        }
        else {
            logEvent(LOG_INVAL, "Second admin OTP invalid for escalation.");
            if (attempt < maxAttempts)
                MessageBoxW(NULL, L"Invalid OTP! Try again.", L"OTP Input", MB_ICONERROR | MB_OK);
        }
    }
    MessageBoxW(NULL, L"Second OTP verification failed.", L"OTP Input", MB_ICONERROR | MB_OK);
    return false;
}

// ======== Admin Privilege Check ========
bool IsProcessElevated(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return false;
    HANDLE hToken = NULL;
    BOOL elevated = FALSE;
    TOKEN_ELEVATION elevation;
    DWORD dwSize = sizeof(TOKEN_ELEVATION);
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
            elevated = elevation.TokenIsElevated;
        CloseHandle(hToken);
    }
    CloseHandle(hProcess);
    return elevated ? true : false;
}

// ======== Enhanced Command Detection ========
bool isBenignCommand(const std::wstring& cmdLine) {
    std::wstring lowerCmd = cmdLine;
    std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::towlower);

    const std::vector<std::wstring> benignPatterns = {
        L"dir", L"cd ", L"echo", L"type ", L"copy ",
        L"help", L"cls", L"exit", L"ping ", L"ipconfig",
        L"get-help", L"get-command", L"get-process", L"get-service"
    };

    for (const auto& pattern : benignPatterns) {
        if (lowerCmd.find(pattern) == 0) { // Starts with
            return true;
        }
    }
    return false;
}

bool isSuspiciousCommand(const std::wstring& cmdLine) {
    std::wstring lowerCmd = cmdLine;
    std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::towlower);

    const std::vector<std::wstring> maliciousPatterns = {
        L"invoke-expression", L"iex", L"downloadstring", L"webclient",
        L"start-process", L"bypass", L"encodedcommand", L" -e ", L" -enc ",
        L"hidden", L" -windowstyle hidden", L" -w hidden", L"new-object",
        L"scriptblock", L"regsvr32", L"certutil -urlcache", L"bitsadmin",
        L"mshta", L"javascript:", L"vbscript:", L"powershell -nop",
        L"powershell -exec bypass", L"schtasks /create", L"wmic /node:",
        L"psexec", L"net user", L"net localgroup administrators",
        L"vssadmin delete shadows", L"add-mpPreference -exclusionpath",
        L"set-mppreference -disable", L"disableantispyware", L"disableantivirus",
        L"disablewindowsdefender", L"stop-service -name", L"sc config",
        L"sc stop", L"taskkill /f /im", L"bcdedit.exe /set",
        L"fsutil behavior set", L"reg add", L"reg delete", L"netsh firewall",
        L"netsh advfirewall", L"wscript.shell", L"shell.application",
        L"get-wmiobject", L"get-ciminstance", L"winmgmts:", L"win32_process",
        L"start-process -verb runas"
    };

    for (const auto& pattern : maliciousPatterns) {
        if (lowerCmd.find(pattern) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

bool isDangerousLolbinUsage(const std::wstring& exeName, const std::wstring& cmdLine) {
    std::wstring lowerExe = exeName;
    std::transform(lowerExe.begin(), lowerExe.end(), lowerExe.begin(), ::towlower);

    std::wstring lowerCmd = cmdLine;
    std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::towlower);

    if (lowerExe == L"powershell.exe") {
        return (lowerCmd.find(L"-nop") != std::wstring::npos ||
            lowerCmd.find(L"-exec bypass") != std::wstring::npos ||
            lowerCmd.find(L"-encodedcommand") != std::wstring::npos);
    }
    else if (lowerExe == L"cmd.exe") {
        return (lowerCmd.find(L"/c powershell") != std::wstring::npos ||
            lowerCmd.find(L"/c start ") != std::wstring::npos);
    }
    else if (lowerExe == L"regsvr32.exe") {
        return (lowerCmd.find(L"/i:") != std::wstring::npos ||
            lowerCmd.find(L"/s ") != std::wstring::npos ||
            lowerCmd.find(L"scrobj.dll") != std::wstring::npos);
    }
    else if (lowerExe == L"mshta.exe") {
        return true; // Always dangerous
    }
    else if (lowerExe == L"rundll32.exe") {
        return (lowerCmd.find(L"javascript:") != std::wstring::npos ||
            lowerCmd.find(L"vbscript:") != std::wstring::npos);
    }
    else if (lowerExe == L"wscript.exe" || lowerExe == L"cscript.exe") {
        return (lowerCmd.find(L".vbs") != std::wstring::npos ||
            lowerCmd.find(L".js") != std::wstring::npos);
    }
    else if (lowerExe == L"msbuild.exe") {
        return (lowerCmd.find(L".csproj") != std::wstring::npos);
    }
    else if (lowerExe == L"installutil.exe") {
        return true; // Always dangerous
    }

    return false;
}

bool shouldIntercept(const std::wstring& exeName, const std::wstring& cmdLine) {
    if (isBenignCommand(cmdLine)) return false;
    if (isSuspiciousCommand(cmdLine)) return true;
    if (isDangerousLolbinUsage(exeName, cmdLine)) return true;
    return false;
}

// ======== LOLBIN List ===============
const std::vector<std::wstring> lolbins = {
    L"acccheckconsole.exe", L"addinutil.exe", L"adplus.exe", L"advpack.dll", L"agentexecutor.exe",
    L"appcert.exe", L"appinstaller.exe", L"appvlp.exe", L"aspnet_compiler.exe", L"at.exe",
    L"atbroker.exe", L"bash.exe", L"bginfo.exe", L"bitsadmin.exe", L"cdb.exe", L"certoc.exe",
    L"certreq.exe", L"certutil.exe", L"cipher.exe", L"cl_invocation.ps1", L"cl_loadassembly.ps1",
    L"cl_mutexverifiers.ps1", L"cmd.exe", L"cmdkey.exe", L"cmdl32.exe", L"cmstp.exe", L"colorcpl.exe",
    L"computerdefaults.exe", L"comsvcs.dll", L"configsecuritypolicy.exe", L"conhost.exe", L"control.exe",
    L"coregen.exe", L"createdump.exe", L"csc.exe", L"cscript.exe", L"csi.exe", L"customshellhost.exe",
    L"datasvcutil.exe", L"defaultpack.exe", L"desktopimgdownldr.exe", L"devicecredentialdeployment.exe",
    L"devinit.exe", L"devtoolslauncher.exe", L"devtunnel.exe", L"dfshim.dll", L"dfsvc.exe", L"diantz.exe",
    L"diskshadow.exe", L"dnscmd.exe", L"dnx.exe", L"dotnet.exe", L"dsdbutil.exe", L"dtutil.exe",
    L"dump64.exe", L"dumpminitool.exe", L"dxcap.exe", L"ecmangen.exe", L"esentutl.exe", L"eventvwr.exe",
    L"excel.exe", L"expand.exe", L"explorer.exe", L"extexport.exe", L"extrac32.exe", L"findstr.exe",
    L"finger.exe", L"fltmc.exe", L"forfiles.exe", L"fsi.exe", L"fsianycpu.exe", L"fsutil.exe",
    L"ftp.exe", L"gpscript.exe", L"hh.exe", L"ie4uinit.exe", L"ieadvpack.dll", L"iediagcmd.exe",
    L"ieexec.exe", L"ieframe.dll", L"ilasm.exe", L"imewdbld.exe", L"infdefaultinstall.exe",
    L"installutil.exe", L"jsc.exe", L"launch-vsdevshell.ps1", L"ldifde.exe", L"makecab.exe",
    L"mavinject.exe", L"mftrace.exe", L"microsoft.nodejstools.pressanykey.exe",
    L"microsoft.workflow.compiler.exe", L"mmc.exe", L"mpcmdrun.exe", L"msaccess.exe", L"msbuild.exe",
    L"msconfig.exe", L"msdeploy.exe", L"msdt.exe", L"msedge.exe", L"msedge_proxy.exe",
    L"msedgewebview2.exe", L"mshta.exe", L"mshtml.dll", L"msiexec.exe", L"msohtmed.exe", L"mspub.exe",
    L"msxsl.exe", L"netsh.exe", L"ngen.exe", L"ntdsutil.exe", L"odbcconf.exe", L"offlinescannershell.exe",
    L"onedrivestandaloneupdater.exe", L"openconsole.exe", L"pcalua.exe", L"pcwrun.exe", L"pcwutl.dll",
    L"pester.bat", L"pktmon.exe", L"pnputil.exe", L"powerpnt.exe", L"presentationhost.exe", L"print.exe",
    L"printbrm.exe", L"procdump.exe", L"protocolhandler.exe", L"provlaunch.exe", L"psr.exe",
    L"pubprn.vbs", L"rasautou.exe", L"rcsi.exe", L"rdrleakdiag.exe", L"reg.exe", L"regasm.exe",
    L"regedit.exe", L"regini.exe", L"register-cimprovider.exe", L"regsvcs.exe", L"regsvr32.exe",
    L"remote.exe", L"replace.exe", L"rpcping.exe", L"rundll32.exe", L"runexehelper.exe", L"runonce.exe",
    L"runscripthelper.exe", L"sc.exe", L"schtasks.exe", L"scriptrunner.exe", L"scrobj.dll",
    L"setres.exe", L"settingsynchost.exe", L"setupapi.dll", L"sftp.exe", L"shdocvw.dll", L"shell32.dll",
    L"shimgvw.dll", L"sqldumper.exe", L"sqlps.exe", L"sqltoolsps.exe", L"squirrel.exe", L"ssh.exe",
    L"stordiag.exe", L"syncappvpublishingserver.exe", L"syncappvpublishingserver.vbs", L"syssetup.dll",
    L"tar.exe", L"te.exe", L"teams.exe", L"testwindowremoteagent.exe", L"tracker.exe", L"ttdinject.exe",
    L"tttracer.exe", L"unregmp2.exe", L"update.exe", L"url.dll", L"utilityfunctions.ps1", L"vbc.exe",
    L"verclsid.exe", L"visio.exe", L"visualuiaverifynative.exe", L"vsdiagnostics.exe", L"vshadow.exe",
    L"vsiisexelauncher.exe", L"vsjitdebugger.exe", L"vslaunchbrowser.exe", L"vsls-agent.exe",
    L"vstest.console.exe", L"wab.exe", L"wbadmin.exe", L"wbemtest.exe", L"wfc.exe", L"wfmformat.exe",
    L"winfile.exe", L"winget.exe", L"winproj.exe", L"winrm.vbs", L"winword.exe", L"wlrmdr.exe",
    L"wmic.exe", L"workfolders.exe", L"wscript.exe", L"wsl.exe", L"wsreset.exe", L"wt.exe",
    L"wuauclt.exe", L"xbootmgrsleep.exe", L"xsd.exe", L"xwizard.exe", L"zipfldr.dll"
};

bool isLolbin(const std::wstring& exeName) {
    std::wstring lower = exeName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    return std::find(lolbins.begin(), lolbins.end(), lower) != lolbins.end();
}

bool isExecutableFile(const std::wstring& path) {
    static const std::vector<std::wstring> exts = {
        L".exe", L".bat", L".cmd", L".ps1", L".vbs", L".js", L".wsf", L".msi", L".scr"
    };
    std::wstring ext = PathFindExtensionW(path.c_str());
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    return std::find(exts.begin(), exts.end(), ext) != exts.end();
}

bool containsDownloadAction(const std::wstring& cmdLine) {
    std::wstring cmd = cmdLine;
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::towlower);
    return
        cmd.find(L"invoke-webrequest") != std::wstring::npos ||
        cmd.find(L"wget") != std::wstring::npos ||
        cmd.find(L"curl") != std::wstring::npos ||
        cmd.find(L"bitsadmin") != std::wstring::npos ||
        cmd.find(L"certutil") != std::wstring::npos ||
        cmd.find(L"-downloadfile") != std::wstring::npos ||
        cmd.find(L"start-bitstransfer") != std::wstring::npos ||
        cmd.find(L"http://") != std::wstring::npos ||
        cmd.find(L"https://") != std::wstring::npos;
}

void showPopup(const std::wstring& text) {
    MessageBoxW(NULL, text.c_str(), L"lolblockotp ALERT", MB_ICONWARNING | MB_OK);
}

// ======== Normal OTP GUI (not console!) =========
bool promptForOtpWithRestriction(const std::wstring& baseFileName, const std::wstring& fullPath, DWORD pid) {
    for (int attempt = 1; attempt <= MAX_OTP_ATTEMPTS; ++attempt) {
        std::wostringstream oss;
        oss << L"Enter OTP for "
            << baseFileName << L" (" << fullPath << L") [PID: " << pid << L"]"
            << L" [Attempt " << attempt << L"/" << MAX_OTP_ATTEMPTS << L"]: ";
        std::wstring otpInput = PromptForOtpBoxWithTimeout(oss.str(), OTP_TIMEOUT_SEC);
        if (otpInput.empty()) {
            MessageBoxW(NULL, L"OTP prompt timed out.", L"OTP Input", MB_ICONERROR | MB_OK);
            logEvent(LOG_ALL, "Normal OTP prompt timeout; process will be terminated.");
            return false;
        }
        int otpResult = callOtpVerifier("normal", otpInput);
        if (otpResult == 0) {
            std::stringstream ss;
            ss << "OTP CORRECT (via otpverify.exe) for " << std::string(baseFileName.begin(), baseFileName.end())
                << " (" << std::string(fullPath.begin(), fullPath.end()) << ") PID: " << pid;
            logEvent(LOG_ALL, ss.str());
            return true;
        }
        else {
            std::stringstream ss;
            ss << "OTP INVALID (via otpverify.exe) for " << std::string(baseFileName.begin(), baseFileName.end())
                << " (" << std::string(fullPath.begin(), fullPath.end()) << ") PID: " << pid
                << " [Attempt " << attempt << "/" << MAX_OTP_ATTEMPTS << "]";
            logEvent(LOG_INVAL, ss.str());
            if (attempt < MAX_OTP_ATTEMPTS)
                MessageBoxW(NULL, L"Invalid OTP! Try again.", L"OTP Input", MB_ICONERROR | MB_OK);
        }
    }
    MessageBoxW(NULL, L"Max OTP attempts reached.", L"OTP Input", MB_ICONERROR | MB_OK);
    return false;
}

// ======= OTP Prompt with Timeout =======
bool promptForOtpWithTimeout(const std::wstring& baseFileName, const std::wstring& fullPath, DWORD pid, int timeout_seconds) {
    auto otpResultPromise = std::make_shared<std::promise<bool>>();
    auto otpResultFuture = otpResultPromise->get_future();

    g_threadPool->enqueue([otpResultPromise, baseFileName, fullPath, pid]() {
        bool result = promptForOtpWithRestriction(baseFileName, fullPath, pid);
        otpResultPromise->set_value(result);
    });

    if (otpResultFuture.wait_for(std::chrono::seconds(timeout_seconds)) == std::future_status::ready) {
        return otpResultFuture.get();
    }
    else {
        return false;
    }
}
void registry_event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    krabs::parser parser(schema);
    std::wstring keyPath = parser.parse<std::wstring>(L"KeyName");
    std::wstring value = parser.parse<std::wstring>(L"ValueName");

    // Check persistence locations
    const std::vector<std::wstring> persistenceKeys = {
        L"\\Run\\", L"\\RunOnce\\", L"\\Winlogon\\",
        L"\\Explorer\\", L"\\Policies\\", L"\\Environment\\"
    };

    for (const auto& key : persistenceKeys) {
        if (keyPath.find(key) != std::wstring::npos) {
            std::wstring alert = L"Registry persistence attempt: " + keyPath;
            logEvent(LOG_MAL, std::string(alert.begin(), alert.end()));
            // Registry rollback logic
            HKEY hRoot = NULL;
            std::wstring subKey = keyPath;
            // Determine root key (simplified)
            if (subKey.find(L"HKEY_LOCAL_MACHINE\\") == 0) {
                hRoot = HKEY_LOCAL_MACHINE;
                subKey = subKey.substr(19); // Remove root prefix
            } else if (subKey.find(L"HKEY_CURRENT_USER\\") == 0) {
                hRoot = HKEY_CURRENT_USER;
                subKey = subKey.substr(18);
            }
            // Remove trailing value name if present
            size_t lastSep = subKey.find_last_of(L'\\');
            std::wstring valueName = value;
            std::wstring keyOnly = subKey;
            if (!valueName.empty() && lastSep != std::wstring::npos) {
                keyOnly = subKey.substr(0, lastSep);
            }
            if (hRoot && !valueName.empty()) {
                HKEY hKey;
                if (RegOpenKeyExW(hRoot, keyOnly.c_str(), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                    RegDeleteValueW(hKey, valueName.c_str());
                    RegCloseKey(hKey);
                    logEvent(LOG_ALL, "Registry persistence attempt rolled back: " + std::string(keyPath.begin(), keyPath.end()));
                }
            }
        }
    }
}
// ======== SUSPEND, RESUME, KILL THREADS =========
void suspendProcess(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) { SuspendThread(hThread); CloseHandle(hThread); }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
}

void resumeProcess(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) { ResumeThread(hThread); CloseHandle(hThread); }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
}

void terminateProcess(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProc) { TerminateProcess(hProc, 1); CloseHandle(hProc); }
}

// ======== Escape Commandline For ML-call ========
std::wstring EscapeQuotes(const std::wstring& str) {
    std::wstring s = str;
    size_t pos = 0;
    while ((pos = s.find(L"\"", pos)) != std::wstring::npos) {
        s.insert(pos, L"\\");
        pos += 2;
    }
    return s;
}

bool isMaliciousByPython(DWORD pid, const std::wstring& exeName, const std::wstring& commandLine) {
    std::wstring safeCmd = EscapeQuotes(commandLine);
    std::wostringstream oss;
    oss << L"python analyze.py " << pid << L" \"" << exeName << L"\" \"" << safeCmd << L"\"";
    int result = _wsystem(oss.str().c_str());
    return result != 0;
}

// ========== ETW CALLBACK =========
void process_event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    if (schema.event_id() == 1) {
        krabs::parser parser(schema);
        DWORD pid = 0;
        std::wstring imageFileName, cmdLine;

        try {
            pid = parser.parse<DWORD>(L"ProcessID");
            imageFileName = parser.parse<std::wstring>(L"ImageName");
            cmdLine = parser.parse<std::wstring>(L"CommandLine");
        }
        catch (...) { return; }

        std::wstring baseFileName = imageFileName.substr(imageFileName.find_last_of(L"\\/") + 1);
        std::wstring lowerBase = baseFileName;
        std::transform(lowerBase.begin(), lowerBase.end(), lowerBase.begin(), ::towlower);

        // Log all process starts
        {
            std::stringstream ss;
            ss << "PROCESS: " << std::string(baseFileName.begin(), baseFileName.end()) << " PATH: "
                << std::string(imageFileName.begin(), imageFileName.end())
                << " CMD: " << std::string(cmdLine.begin(), cmdLine.end())
                << " PID: " << pid;
            logEvent(LOG_ALL, ss.str());
        }

        // Check for remote shell parents
        std::wstring parent = getParentProcessName(pid);
        std::vector<std::wstring> remoteParents = {
            L"ssh.exe", L"scp.exe", L"sftp-server.exe",
            L"teamviewer.exe", L"anydesk.exe", L"radmin.exe",
            L"mstsc.exe", L"powershell.exe", L"cmd.exe"
        };
        std::transform(parent.begin(), parent.end(), parent.begin(), ::towlower);
        for (const auto& remoteExe : remoteParents) {
            std::wstring exeLower = remoteExe;
            std::transform(exeLower.begin(), exeLower.end(), exeLower.begin(), ::towlower);
            if (parent == exeLower) {
                suspendProcess(pid);
                g_threadPool->enqueue([=]() {
                    if (!promptForOtpWithTimeout(baseFileName, imageFileName, pid, OTP_TIMEOUT_SEC)) {
                        logEvent(LOG_ALL, "OTP not received (or incorrect) in 2 minutes. Process terminated.");
                        terminateProcess(pid);
                    }
                    else {
                        resumeProcess(pid);
                    }
                    });
                return;
            }
        }

        // Check for download attempts
        if (containsDownloadAction(cmdLine)) {
            std::wstring alert = L"Download attempt detected and blocked:\nProcess: " + baseFileName +
                L"\nCommand: " + cmdLine;
            std::wcout << L"[Download Alert] " << alert << std::endl;
            logEvent(LOG_MAL, std::string(alert.begin(), alert.end()));
            showPopup(alert);
            terminateProcess(pid);
            return;
        }

        // Check for MOTW
        if (isExecutableFile(imageFileName) && hasMarkOfTheWeb(imageFileName)) {
            std::wstring alert = L"Execution of downloaded file is blocked!\nPath: " + imageFileName;
            std::wcout << L"[MOTW Block] " << alert << std::endl;
            logEvent(LOG_MAL, std::string(alert.begin(), alert.end()));
            showPopup(alert);
            terminateProcess(pid);
            return;
        }

        // Check if we should intercept this process
        if (shouldIntercept(baseFileName, cmdLine)) {
            std::wcout << L"Suspicious command detected: " << baseFileName
                << L" (PID: " << pid << L")"
                << L"\n   CommandLine: " << cmdLine << std::endl;

            suspendProcess(pid);
            g_threadPool->enqueue([pid, baseFileName, imageFileName, cmdLine]() {
                if (!promptForOtpWithTimeout(baseFileName, imageFileName, pid, OTP_TIMEOUT_SEC)) {
                    std::wcout << L"OTP invalid, max attempts reached, or timed out. Terminating process.\n";
                    std::stringstream ss;
                    ss << "Terminate (OTP incorrect or timeout): " << std::string(baseFileName.begin(), baseFileName.end())
                        << " (" << std::string(imageFileName.begin(), imageFileName.end())
                        << ") CMD: " << std::string(cmdLine.begin(), cmdLine.end())
                        << " PID: " << pid;
                    logEvent(LOG_INVAL, ss.str());
                    logEvent(LOG_ALL, ss.str());
                    terminateProcess(pid);
                    return;
                }
                else if (isMaliciousByPython(pid, baseFileName, cmdLine)) {
                    std::wcout << L"Process flagged malicious.\n";
                    if (IsProcessElevated(pid)) {
                        if (requireTwoDifferentOtps(baseFileName, imageFileName, pid)) {
                            std::wcout << L"Both admin OTPs correct. Resuming process.\n";
                            logEvent(LOG_ALL, "Malicious verdict overridden by two OTPs; process resumed.");
                            resumeProcess(pid);
                        }
                        else {
                            std::wcout << L"Admin OTP override timed out or failed. Terminating process.\n";
                            logEvent(LOG_ALL, "Admin OTP override timed out or failed. Process terminated.");
                            terminateProcess(pid);
                        }
                    }
                    else {
                        std::wcout << L"Admin override failed. Terminating process.\n";
                        std::stringstream ss;
                        ss << "Malicious command blocked: " << std::string(baseFileName.begin(), baseFileName.end())
                            << " (" << std::string(imageFileName.begin(), imageFileName.end())
                            << ") CMD: " << std::string(cmdLine.begin(), cmdLine.end())
                            << " PID: " << pid;
                        logEvent(LOG_MAL, ss.str());
                        terminateProcess(pid);
                    }
                }
                else {
                    std::wcout << L"Process allowed after OTP verification.\n";
                    resumeProcess(pid);
                }
                });
            return;
        }

        // Check for LOLBIN usage
        if (isLolbin(baseFileName)) {
            std::wcout << L"LOLBIN detected: " << baseFileName
                << L" (PID: " << pid << L")"
                << L"\n   CommandLine: " << cmdLine << std::endl;

            suspendProcess(pid);
            g_threadPool->enqueue([pid, baseFileName, imageFileName, cmdLine]() {
                if (!promptForOtpWithTimeout(baseFileName, imageFileName, pid, OTP_TIMEOUT_SEC)) {
                    std::wcout << L"OTP invalid, max attempts reached, or timed out. Terminating process.\n";
                    std::stringstream ss;
                    ss << "Terminate LOLBIN (OTP incorrect or timeout): " << std::string(baseFileName.begin(), baseFileName.end())
                        << " (" << std::string(imageFileName.begin(), imageFileName.end())
                        << ") CMD: " << std::string(cmdLine.begin(), cmdLine.end())
                        << " PID: " << pid;
                    logEvent(LOG_INVAL, ss.str());
                    logEvent(LOG_ALL, ss.str());
                    terminateProcess(pid);
                    return;
                }
                else if (isDangerousLolbinUsage(baseFileName, cmdLine)) {
                    std::wcout << L"Dangerous LOLBIN usage detected.\n";
                    if (IsProcessElevated(pid)) {
                        if (requireTwoDifferentOtps(baseFileName, imageFileName, pid)) {
                            std::wcout << L"Both admin OTPs correct. Resuming process.\n";
                            logEvent(LOG_ALL, "LOLBIN verdict overridden by two OTPs; process resumed.");
                            resumeProcess(pid);
                        }
                        else {
                            std::wcout << L"Admin OTP override timed out or failed. Terminating process.\n";
                            logEvent(LOG_ALL, "Admin OTP override timed out or failed. Process terminated.");
                            terminateProcess(pid);
                        }
                    }
                    else {
                        std::wcout << L"Admin override failed. Terminating process.\n";
                        std::stringstream ss;
                        ss << "Dangerous LOLBIN blocked: " << std::string(baseFileName.begin(), baseFileName.end())
                            << " (" << std::string(imageFileName.begin(), imageFileName.end())
                            << ") CMD: " << std::string(cmdLine.begin(), cmdLine.end())
                            << " PID: " << pid;
                        logEvent(LOG_MAL, ss.str());
                        terminateProcess(pid);
                    }
                }
                else {
                    std::wcout << L"LOLBIN usage allowed after OTP verification.\n";
                    resumeProcess(pid);
                }
                });
            return;
        }

        // Fileless execution detection: suspicious memory + PowerShell
        if (isExecutableFile(imageFileName) && is_hollowed_process(pid)) {
            std::wstring alert = L"Process hollowing detected!\nPath: " + imageFileName;
            std::wcout << L"[Hollowing Block] " << alert << std::endl;
            logEvent(LOG_MAL, std::string(alert.begin(), alert.end()));
            showPopup(alert);
            terminateProcess(pid);
            return;
        }
    }
}
bool is_hollowed_process(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;
    HMODULE hMods[1024];
    DWORD cbNeeded;
    bool hollowed = false;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        TCHAR szModName[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, hMods[0], szModName, MAX_PATH)) {
            // Read disk image
            std::ifstream diskFile(szModName, std::ios::binary);
            std::vector<char> diskData((std::istreambuf_iterator<char>(diskFile)), std::istreambuf_iterator<char>());
            // Read memory image
            MODULEINFO modInfo;
            if (GetModuleInformation(hProcess, hMods[0], &modInfo, sizeof(modInfo))) {
                std::vector<char> memData(modInfo.SizeOfImage);
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(hProcess, modInfo.lpBaseOfDll, memData.data(), modInfo.SizeOfImage, &bytesRead)) {
                    // Hash both
                    HCRYPTPROV hProv = 0;
                    HCRYPTHASH hHashDisk = 0, hHashMem = 0;
                    BYTE hashDisk[32], hashMem[32];
                    DWORD hashLen = 32;
                    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHashDisk) &&
                            CryptHashData(hHashDisk, (BYTE*)diskData.data(), (DWORD)diskData.size(), 0) &&
                            CryptGetHashParam(hHashDisk, HP_HASHVAL, hashDisk, &hashLen, 0)) {
                            if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHashMem) &&
                                CryptHashData(hHashMem, (BYTE*)memData.data(), (DWORD)memData.size(), 0) &&
                                CryptGetHashParam(hHashMem, HP_HASHVAL, hashMem, &hashLen, 0)) {
                                if (memcmp(hashDisk, hashMem, hashLen) != 0) hollowed = true;
                                CryptDestroyHash(hHashMem);
                            }
                            CryptDestroyHash(hHashDisk);
                        }
                        CryptReleaseContext(hProv, 0);
                    }
                }
            }
        }
    }
    CloseHandle(hProcess);
    return hollowed;
}
int main() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    if (!isElevated) {
        MessageBoxW(NULL, L"This program requires administrator privileges to monitor system events. Please re-run as an Administrator.", L"Error", MB_ICONERROR | MB_OK);
        return 1;
    }
    try {
        // Initialize thread pool with 4 workers
        ThreadPool pool(4);
        g_threadPool = &pool;
        // Set up the ETW trace
        krabs::user_trace trace(L"lolblockotp");
        krabs::provider<> provider(krabs::guid(L"{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")); // Microsoft-Windows-Kernel-Process

        provider.any(0x10); // WINEVENT_KEYWORD_PROCESS
        provider.add_on_event_callback(process_event_callback);
        trace.enable(provider);
        // Memory operations provider
        krabs::provider<> mem_provider(krabs::guid(L"{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}"));
        mem_provider.any(0xFFFFFFFF); // All events
        mem_provider.add_on_event_callback(memory_event_callback);
        trace.enable(mem_provider);

        // DLL load provider
        krabs::provider<> dll_provider(krabs::guid(L"{2cb15d1d-5fc1-11d2-abe1-00a0c911f518}"));
        dll_provider.add_on_event_callback(dll_load_callback);
        trace.enable(dll_provider);

        // Registry provider
        krabs::provider<> reg_provider(krabs::guid(L"{70EB4F03-C1DE-4F73-A051-33D13D5413BD}"));
        reg_provider.add_on_event_callback(registry_event_callback);
        trace.enable(reg_provider);
        // Start the trace
        std::cout << "Starting lolblockotp monitoring..." << std::endl;
        logEvent(LOG_ALL, "lolblockotp service started");
        trace.start();

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        logEvent(LOG_ALL, std::string("Fatal error: ") + e.what());
        return 1;
    }
    g_threadPool = nullptr;
    return 0;
}