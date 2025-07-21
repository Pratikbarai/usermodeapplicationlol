#include "krabs/krabs.hpp"
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
#include <cstdio>
#include <ctime>
#include <sstream>
#pragma comment(lib, "shlwapi.lib")

constexpr int MAX_OTP_ATTEMPTS = 3;
std::mutex logMutex;

const std::string LOG_ALL = "log_all.txt";
const std::string LOG_MAL = "log_otp_correct_malicious.txt";
const std::string LOG_INVAL = "log_otp_incorrect.txt";

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

// ======== Require Two Distinct OTPs For Admin Escalation (GUI) ========
bool requireTwoDifferentOtps(const std::wstring& baseFileName, const std::wstring& fullPath, DWORD pid)
{
    int maxAttempts = 2;
    std::wstring otp1, otp2;

    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        std::wostringstream oss;
        oss << L"Enter ADMIN OTP for " << baseFileName
            << L"\nPath: " << fullPath << L"\nPID: " << pid
            << L"\n[First OTP, Attempt " << attempt << L"/" << maxAttempts << L"]:";
        otp1 = PromptForOtpBox(oss.str());

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
    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        std::wostringstream oss;
        oss << L"Enter ADMIN OTP for " << baseFileName
            << L"\nPath: " << fullPath << L"\nPID: " << pid
            << L"\n[Second OTP, Attempt " << attempt << L"/" << maxAttempts << L"]: (Different from first)";
        otp2 = PromptForOtpBox(oss.str());

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
// ======== General Process Helper Listeners ===============
const std::vector<std::wstring> lolbins = {
    L"acccheckconsole.exe", L"addinutil.exe", L"adplus.exe", L"advpack.dll", L"agentexecutor.exe", L"appcert.exe",
    L"appinstaller.exe", L"appvlp.exe", L"aspnet_compiler.exe", L"at.exe", L"atbroker.exe", L"bash.exe",
    L"bginfo.exe", L"bitsadmin.exe", L"cdb.exe", L"certoc.exe", L"certreq.exe", L"certutil.exe", L"cipher.exe",
    L"cl_invocation.ps1", L"cl_loadassembly.ps1", L"cl_mutexverifiers.ps1", L"cmd.exe", L"cmdkey.exe", L"cmdl32.exe",
    L"cmstp.exe", L"colorcpl.exe", L"computerdefaults.exe", L"comsvcs.dll", L"configsecuritypolicy.exe",
    L"conhost.exe", L"control.exe", L"coregen.exe", L"createdump.exe", L"csc.exe", L"cscript.exe", L"csi.exe",
    L"customshellhost.exe", L"datasvcutil.exe", L"defaultpack.exe", L"desktopimgdownldr.exe",
    L"devicecredentialdeployment.exe", L"devinit.exe", L"devtoolslauncher.exe", L"devtunnel.exe", L"dfshim.dll",
    L"dfsvc.exe", L"diantz.exe", L"diskshadow.exe", L"dnscmd.exe", L"dnx.exe", L"dotnet.exe", L"dsdbutil.exe",
    L"dtutil.exe", L"dump64.exe", L"dumpminitool.exe", L"dxcap.exe", L"ecmangen.exe", L"esentutl.exe", L"eventvwr.exe",
    L"excel.exe", L"expand.exe", L"explorer.exe", L"extexport.exe", L"extrac32.exe", L"findstr.exe", L"finger.exe",
    L"fltmc.exe", L"forfiles.exe", L"fsi.exe", L"fsianycpu.exe", L"fsutil.exe", L"ftp.exe", L"gpscript.exe", L"hh.exe",
    L"ie4uinit.exe", L"ieadvpack.dll", L"iediagcmd.exe", L"ieexec.exe", L"ieframe.dll", L"ilasm.exe", L"imewdbld.exe",
    L"infdefaultinstall.exe", L"installutil.exe", L"jsc.exe", L"launch-vsdevshell.ps1", L"ldifde.exe", L"makecab.exe",
    L"mavinject.exe", L"mftrace.exe", L"microsoft.nodejstools.pressanykey.exe", L"microsoft.workflow.compiler.exe",
    L"mmc.exe", L"mpcmdrun.exe", L"msaccess.exe", L"msbuild.exe", L"msconfig.exe", L"msdeploy.exe", L"msdt.exe",
    L"msedge.exe", L"msedge_proxy.exe", L"msedgewebview2.exe", L"mshta.exe", L"mshtml.dll", L"msiexec.exe",
    L"msohtmed.exe", L"mspub.exe", L"msxsl.exe", L"netsh.exe", L"ngen.exe", L"ntdsutil.exe", L"odbcconf.exe",
    L"offlinescannershell.exe", L"onedrivestandaloneupdater.exe", L"openconsole.exe", L"pcalua.exe", L"pcwrun.exe",
    L"pcwutl.dll", L"pester.bat", L"pktmon.exe", L"pnputil.exe", L"powerpnt.exe", L"presentationhost.exe",
    L"print.exe", L"printbrm.exe", L"procdump.exe", L"protocolhandler.exe", L"provlaunch.exe", L"psr.exe",
    L"pubprn.vbs", L"rasautou.exe", L"rcsi.exe", L"rdrleakdiag.exe", L"reg.exe", L"regasm.exe", L"regedit.exe",
    L"regini.exe", L"register-cimprovider.exe", L"regsvcs.exe", L"regsvr32.exe", L"remote.exe", L"replace.exe",
    L"rpcping.exe", L"rundll32.exe", L"runexehelper.exe", L"runonce.exe", L"runscripthelper.exe", L"sc.exe",
    L"schtasks.exe", L"scriptrunner.exe", L"scrobj.dll", L"setres.exe", L"settingsynchost.exe", L"setupapi.dll",
    L"sftp.exe", L"shdocvw.dll", L"shell32.dll", L"shimgvw.dll", L"sqldumper.exe", L"sqlps.exe", L"sqltoolsps.exe",
    L"squirrel.exe", L"ssh.exe", L"stordiag.exe", L"syncappvpublishingserver.exe", L"syncappvpublishingserver.vbs",
    L"syssetup.dll", L"tar.exe", L"te.exe", L"teams.exe", L"testwindowremoteagent.exe", L"tracker.exe", L"ttdinject.exe",
    L"tttracer.exe", L"unregmp2.exe", L"update.exe", L"url.dll", L"utilityfunctions.ps1", L"vbc.exe", L"verclsid.exe",
    L"visio.exe", L"visualuiaverifynative.exe", L"vsdiagnostics.exe", L"vshadow.exe", L"vsiisexelauncher.exe",
    L"vsjitdebugger.exe", L"vslaunchbrowser.exe", L"vsls-agent.exe", L"vstest.console.exe", L"wab.exe", L"wbadmin.exe",
    L"wbemtest.exe", L"wfc.exe", L"wfmformat.exe", L"winfile.exe", L"winget.exe", L"winproj.exe", L"winrm.vbs",
    L"winword.exe", L"wlrmdr.exe", L"wmic.exe", L"workfolders.exe", L"wscript.exe", L"wsl.exe", L"wsreset.exe",
    L"wt.exe", L"wuauclt.exe", L"xbootmgrsleep.exe", L"xsd.exe", L"xwizard.exe", L"zipfldr.dll"
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
        std::wstring otpInput = PromptForOtpBox(oss.str());
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
        try { pid = parser.parse<DWORD>(L"ProcessID"); }
        catch (...) { std::wcout << L"Could not get ProcessID. Skipping event.\n"; return; }
        std::wstring imageFileName;
        try { imageFileName = parser.parse<std::wstring>(L"ImageName"); }
        catch (...) { std::wcout << L"Could not parse exe name (ImageName). Skipping event.\n"; return; }
        std::wstring cmdLine;
        try { cmdLine = parser.parse<std::wstring>(L"CommandLine"); }
        catch (...) { cmdLine = L""; }
        std::wstring baseFileName = imageFileName.substr(imageFileName.find_last_of(L"\\/") + 1);
        std::wcout << L"Process started: " << imageFileName << L" (PID: " << pid << L")" << std::endl;
        {
            std::stringstream ss;
            ss << "PROCESS: " << std::string(baseFileName.begin(), baseFileName.end()) << " PATH: "
                << std::string(imageFileName.begin(), imageFileName.end())
                << " CMD: " << std::string(cmdLine.begin(), cmdLine.end())
                << " PID: " << pid;
            logEvent(LOG_ALL, ss.str());
        }
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
                std::thread([=]() {
                    if (!promptForOtpWithRestriction(baseFileName, imageFileName, pid)) {
                        terminateProcess(pid);
                    }
                    else {
                        resumeProcess(pid);
                    }
                    }).detach();
                return;
            }
        }
        if (containsDownloadAction(cmdLine)) {
            std::wstring alert = L"Download attempt detected and blocked:\nProcess: " + baseFileName +
                L"\nCommand: " + cmdLine;
            std::wcout << L"[Download Alert] " << alert << std::endl;
            logEvent(LOG_MAL, std::string(alert.begin(), alert.end()));
            showPopup(alert);
            terminateProcess(pid);
            return;
        }
        if (isExecutableFile(imageFileName) && hasMarkOfTheWeb(imageFileName)) {
            std::wstring alert = L"Execution of downloaded file is blocked!\nPath: " + imageFileName;
            std::wcout << L"[MOTW Block] " << alert << std::endl;
            logEvent(LOG_MAL, std::string(alert.begin(), alert.end()));
            showPopup(alert);
            terminateProcess(pid);
            return;
        }
        if (isLolbin(baseFileName)) {
            std::wcout << L"LOLBIN detected: " << baseFileName
                << L" (PID: " << pid << L")"
                << L"\n   CommandLine: " << cmdLine << std::endl;
            suspendProcess(pid);
            std::thread([pid, baseFileName, imageFileName, cmdLine]() {
                if (!promptForOtpWithRestriction(baseFileName, imageFileName, pid)) {
                    std::wcout << L"OTP invalid or max attempts reached. Terminating process.\n";
                    std::stringstream ss;
                    ss << "Terminate (OTP incorrect): " << std::string(baseFileName.begin(), baseFileName.end())
                        << " (" << std::string(imageFileName.begin(), imageFileName.end())
                        << ") CMD: " << std::string(cmdLine.begin(), cmdLine.end())
                        << " PID: " << pid;
                    logEvent(LOG_INVAL, ss.str());
                    logEvent(LOG_ALL, ss.str());
                    terminateProcess(pid);
                }
                else if (isMaliciousByPython(pid, baseFileName, cmdLine)) {
                    std::wcout << L"Process flagged malicious.\n";
                    if (IsProcessElevated(pid))
                    {
                        if (requireTwoDifferentOtps(baseFileName, imageFileName, pid)) {
                            std::wcout << L"Both admin OTPs correct. Resuming process.\n";
                            logEvent(LOG_ALL, "Malicious verdict overridden by two OTPs; process resumed.");
                            resumeProcess(pid);
                        }
                    }
                    else {
                        std::wcout << L"Admin override failed. Terminating process.\n";
                        std::stringstream ss;
                        ss << "prove to be admin fail . action done by malacious malware: " << std::string(baseFileName.begin(), baseFileName.end())
                            << " (" << std::string(imageFileName.begin(), imageFileName.end())
                            << ") CMD: " << std::string(cmdLine.begin(), cmdLine.end())
                            << " PID: " << pid;
                        logEvent(LOG_MAL, ss.str());
                        logEvent(LOG_ALL, ss.str());
                        terminateProcess(pid);
                    }
                }
                else {
                    std::wcout << L"Process is benign. Resuming.\n";
                    resumeProcess(pid);
                }
                }).detach();
        }
    }
}

// ========= MAIN: ETW and loop ========
int main() {
    try {
        std::wcout << L"LOLBIN Interceptor (ETW, real-time) started.\n";
        krabs::user_trace trace;
        krabs::provider<> process_provider(L"Microsoft-Windows-Kernel-Process");
        process_provider.add_on_event_callback(process_event_callback);
        std::wcout << L"Enabling provider..." << std::endl;
        trace.enable(process_provider);
        std::wcout << L"Provider enabled. Starting trace..." << std::endl;
        trace.start();
    }
    catch (const std::exception& e) {
        std::wcerr << L"Exception: " << e.what() << std::endl;
        system("pause");
    }
    catch (...) {
        std::wcerr << L"Unknown exception occurred!" << std::endl;
        system("pause");
    }
    return 0;
}
