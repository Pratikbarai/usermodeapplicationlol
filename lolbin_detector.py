# lolbin_detector.py
import re
from collections import defaultdict
from datetime import datetime
import logging

class LOLBinDetector:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.patterns = self._load_lolbin_patterns()
        self.whitelist = self._load_whitelist_patterns()
        # Renamed method and attributes
        self.malicious_combined = self._compile_patterns(self.patterns)
        self.whitelist_combined = self._compile_patterns(self.whitelist)
        self.last_command_line = ""
        self.severity_map = self._create_severity_map()
        self.cache = {}  # Initialize cache
        self.cache_size = 1000  # Set cache size
        
    def _load_lolbin_patterns(self):
        """Load optimized patterns from the raw commands"""
        LOLBIN_PATTERNS={
            # AddinUtil.exe patterns
            'AddinUtil.exe': [
                r'-AddinRoot:\.?\\.?\\?',
                r'-PipelineStoreDir:[^\s]+',
                r'-HostView:[^\s]+',
                r'-Addin:[^\s]+\.dll'
            ],
            
            # AppInstaller.exe patterns
            'appInstaller.exe': [
                r'ms-appinstaller:\?source=https?://[^\s]+\.exe',
                r'ms-appinstaller:\?source=https?://[^\s]+\.dll',
                r'ms-appinstaller:\?source=https?://[^\s]+\.bat',
                r'ms-appinstaller:\?source=https?://[^\s]+\.cmd',
                r'ms-appinstaller:\?source=https?://[^\s]+\.ps1',
                r'ms-appinstaller:\?source=https?://[^\s]+\.js',
                r'ms-appinstaller:\?source=https?://[^\s]+\.vbs',
                r'ms-appinstaller:\?source=https?://[^\s%]*%2[eE][xX][eE]'
            ],
            
            # aspnet_compiler.exe patterns
            'aspnet_compiler.exe': [
                r'-p\s+[cC]:\\users\\[^\s]+\\desktop\\[^\s]+',
                r'-p\s+[^\s]*\\(temp|downloads|public)\\[^\s]+',
                r'-u.*-f',
                r'-v\s+none\s+-p\s+[^\s]+',
                r'-f\s+[cC]:\\users\\[^\s]+\\desktop\\[^\s]+',
                r'-p\s+(?!.*inetpub).*'
            ],
            
            # at.exe patterns
            'at.exe': [
                r'\d{1,2}:\d{2}\s+/interactive\s+/every:[^\s]+\s+cmd\s+/c\s+[^\s]+',
                r'/every:[a-z,]+.*(cmd|powershell|wscript|cscript)\s+/c\s+[^\s]+'
            ],
            
            # atbroker.exe patterns
            'atbroker.exe': [
                r'/start\s+[^\s]+'
            ],
            
            # bash.exe patterns
            'bash.exe': [
                r'-c\s+"?cmd\s+/c\s+[^\s]+',
                r'-c\s+"?socat\s+tcp-connect:[\d.]+:\d+\s+exec:\w+',
                r'-c\s+[\'"]?cat\s+[^\s]+\s+>\s+/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+'
            ],
            
            # bitsadmin.exe patterns
            'bitsadmin.exe': [
                r'/addfile\s+\d+\s+(https?|ftp)://[^\s]+\s+[^\s]+',
                r'/addfile\s+\d+\s+c:\\windows\\system32\\[^\s]+\s+[^\s]+',
                r'/SetNotifyCmdLine\s+\d+\s+[^\s]+:(exe|cmd|ps1)\s+NULL',
                r'/SetNotifyCmdLine\s+\d+\s+[^\s]+\.(exe|cmd|bat|ps1)\s+NULL',
                r'/create\s+\d+\s+.*(/addfile|/SetNotifyCmdLine|/resume|/complete|/reset)',
                r'/reset\s*$',
                r'/resume\s+\d+\s+.*(/SetNotifyCmdLine|/complete)',
                r'/create\s+\d+\s*&\s*bitsadmin'
            ],
            
            # certoc.exe patterns
            'certoc.exe': [
                r'-LoadDLL\s+c:\\windows\\temp\\[^\s]+\.dll',
                r'-GetCACAPS\s+https?://[^\s]+\.ps1'
            ],
            
            # certreq.exe patterns
            'certreq.exe': [
                r'-Post\s+-config\s+https?://[^\s]+\s+[cC]:\\windows\\temp\\[^\s]+',
                r'-Post\s+-config\s+https?://[^\s]+'
            ],
            
            # certutil.exe patterns
            'certutil.exe': [
                r'certutil(\.exe)?\s+-urlcache\s+(?:-split\s+)?-f\s+https?://',
                r'certutil(\.exe)?\s+-urlcache\s+-f\s+https?://[^\s]+\s+[^\s]+',

                # Obfuscated encode/decode commands
                r'certutil\s+-[de]+n?code',
                r'-urlcache\s+-f\s+https?://[^\s]+\s+[^\s]+:[^\s]+',
                r'-urlcache\s+(?:-split\s+)?-f\s+https?://[^\s]+\s+[^\s]+',
                r'-urlcache\s+-f\s+https?://[^\s]+\s+[^\s]+',
                r'-verifyctl\s+-f\s+https?://[^\s]+',
                r'-URL\s+https?://[^\s]+',
                r'-urlcache\s+-f\s+https?://[^\s]+\s+[^\s]+:[^\s]+',
                r'-encode\s+[^\s]+\s+[^\s]+\.base64',
                r'-decode\s+[^\s]+\.base64\s+[^\s]+\.(exe|dll|ps1|bat|cmd)',
                r'-decodehex\s+[^\s]+\.hex\s+[^\s]+\.(exe|dll|ps1|bat|cmd)'
            ],
            
            # cipher.exe patterns
            'cipher.exe': [
                r'/w:\s*[cC]:\\windows\\temp\\[^\s]+'
            ],
            'forfiles.exe': [
                r'/c\s+"cmd\s+/c\s+[^"]+"'
]
,
            
            # cmd.exe patterns
            'cmd.exe': [
                r'/c\s+.*?(curl|bitsadmin|certutil|powershell)[\x00-\x20]+',
                # Echo to create script files
                r'echo\s+.*?>\s+.*?\.(vbs|js|bat)',
                # String concatenation with environment variables
                r'%[A-Z]+%.*%[A-Z]+%'
                r'forfiles\s+/[^\s]+\s+/m\s+[^\s]+\s+/c\s+"cmd\s+/c\s+[^"]+"',
                r'cmd\s+/c\s+[^\s]+\.exe\s+&&\s+cmd\s+/c\s+[^\s]+\.exe',
                 # Alternate Data Stream (ADS) - hide payload
                r'type\s+[^\s]+\.(exe|dll|bat|cmd|ps1)\s+>\s+[^\s]+:[^\s]+',
                # Execute ADS payload
                r'start\s+\.?\\?[^\s]+:[^\s]+',
                # (Optional) echo into ADS
                r'echo\s+.+\s+>\s+[^\s]+:[^\s]+',
                r'/c\s+echo\s+regsvr32\.exe\s+\^/s\s+\^/u\s+\^/i:https?://[^\s]+\s+\^scrobj\.dll\s+>\s+\S+:payload\.bat',
                r'-\s*<\s*\S+:payload\.bat',
                r'set\s+comspec\s*=\s*[^&]+\.exe\s*&\s*cscript\s+[^\s"]*manage-bde\.wsf',
                r'copy\s+[^\s"]+evil\.exe\s+[^\s"]+manage-bde\.exe\s*&\s*cd\s+[^\s"]+\s*&\s*cscript(\.exe)?\s+[^\s"]*manage-bde\.wsf',
                r'Pester\.bat\s+(?:/help|\?|-\?|/\?)\s*"?\$null;\s*cmd\s*/c\s+[^\s"]+\.exe"?',
                r'Pester\.bat\s*;\s*[^\s"]+\.exe',
                r'rmdir\s+%temp%\\lolbin\s+/s\s+/q\s+2>nul\s+&\s+mkdir\s+"%temp%\\lolbin\\Windows Media Player"\s+&\s+copy\s+C:\\Windows\\System32\\calc\.exe\s+"%temp%\\lolbin\\Windows Media Player\\wmpnscfg\.exe"\s+>nul\s+&&\s+cmd\s+/V\s+/C\s+"set\s+"ProgramW6432=%temp%\\lolbin"\s+&&\s+unregmp2\.exe\s+/HideWMP"'
            ],
            
            # type.exe patterns
            'type.exe': [
                r'type\s+\\\\[^\s]+\\[cC]\$\\windows\\temp\\[^\s]+\s*>\s*[cC]:\\windows\\temp\\[^\s]+',
                r'type\s+[cC]:\\windows\\temp\\[^\s]+\s*>\s+\\\\[^\s]+\\[cC]\$\\windows\\temp\\[^\s]+'
            ],
            
            # cmdkey.exe patterns
            'cmdkey.exe': [
                r'/list'
            ],
            
            # cmdl32.exe patterns
            'cmdl32.exe': [
                r'/vpn\s+/lan\s+%cd%\\config'
            ],
            
            # cmstp.exe patterns
            'cmstp.exe': [
                r'/ni\s+/s\s+[cC]:\\windows\\temp\\[^\s]+\.inf',
                r'/ni\s+/s\s+https?://[^\s]+\.inf'
            ],
            
            # colorcpl.exe patterns
            'colorcpl.exe': [
                r'\S+\.(exe|dll|inf|ocx)'
            ],
            
            # ComputerDefaults.exe patterns
            'ComputerDefaults.exe': [
                r'\.(exe|dll|bat|cmd|ps1)\b',  # Focus on extension abuse
                r'https?://\S+\.(scr|pif|jar)'
            ],
            
            # ConfigSecurityPolicy.exe patterns
            'ConfigSecurityPolicy.exe': [
                r'[cC]:\\Windows\\Temp\\[^\s]+',
                r'https?://[^\s]+'
            ],
            
            # conhost.exe patterns
            'conhost.exe': [
                r'--headless\s+cmd\s+/c\s+[cC]:\\windows\\system32\\[^\s]+',
                r'cmd\s+/c\s+[cC]:\\windows\\system32\\[^\s]+'
            ],
            
            # control.exe patterns
            'control.exe': [
                r'[cC]:\\Windows\\Temp\\[^\s]+:\w+\.dll',
                r'[cC]:\\Windows\\Temp\\[^\s]+\.cpl'
            ],
            
            # csc.exe patterns
            'csc.exe': [
                r'-out:[^\s]+\.exe\s+[^\s]+\.cs',
                r'-target:library\s+[^\s]+\.cs'
            ],
            
            # cscript.exe patterns
            'cscript.exe': [
                r'//e:vbscript\s+[cC]:\\Windows\\Temp\\[^\s]+:\w+\.vbs',
                r'pubprn\.vbs\s+\d{1,3}(\.\d{1,3}){3}\s+script:https?:\/\/[^\s"]+\.sct',
                r'cscript(\.exe)?\s+[^\s"]*manage-bde\.wsf',
                r'%SystemDrive%\\BypassDir\\cscript\s+//nologo\s+[^\s"]*winrm\.vbs\s+get\s+wmicimv2/Win32_Process\?Handle=\d+\s+-format:pretty'
            ],
            
            # CustomShellHost.exe patterns
            'CustomShellHost.exe': [
                r'.*'
            ],
            
            # DataSvcUtil.exe patterns
            'DataSvcUtil.exe': [
                r'/out:[cC]:\\Windows\\Temp\\[^\s]+',
                r'/uri:https?://[^\s]+'
            ],
            
            # desktopimgdownldr.exe patterns
            'desktopimgdownldr.exe': [
                r'/lockscreenurl:https?://[^\s]+',
                r'/eventName:desktopimgdownldr'
            ],
            
            # DeviceCredentialDeployment.exe patterns
            'DeviceCredentialDeployment.exe': [
                r'.*'
            ],
            
            # diantz.exe patterns
            'diantz.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.exe\s+C:\\Windows\\Temp\\[^\s]+:\w+\.cab',
                r'\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.exe\s+C:\\Windows\\Temp\\[^\s]+(:[^\s]+\.cab)?',
                r'/f\s+[^\s]+\.ddf'
            ],
            
            # diskshadow.exe patterns
            'diskshadow.exe': [
                r'/s\s+[^\s]+\.txt',
                r'diskshadow>\s*exec\s+[^\s]+\.exe'
            ],
            
            # dnscmd.exe patterns
            'dnscmd.exe': [
                r'/serverlevelplugindll\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.dll'
            ],
            
            # esentutl.exe patterns
            'esentutl.exe': [
                r'/y\s+C:\\Windows\\Temp\\[^\s]+\.(exe|vbs)\s+/d\s+C:\\Windows\\Temp\\[^\s]+',
                r'/y\s+/vss\s+c:\\windows\\ntds\\ntds\.dit\s+/d\s+C:\\Windows\\Temp\\[^\s]+\.dit',
                r'/y\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.(exe|vbs)\s+/d\s+C:\\Windows\\Temp\\[^\s]+',
                r'/y\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.source\.exe\s+/d\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.dest\.exe\s+/o'
            ],
            
            # eventvwr.exe patterns
            'eventvwr.exe': [
                r'^eventvwr\.exe$',
                r'ysoserial\.exe.*cmd\s+/c\s+c:\\windows\\system32\\calc\.exe.*eventvwr\.exe'
            ],
            
            # expand.exe patterns
            'expand.exe': [
                r'\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.bat\s+C:\\Windows\\Temp\\[^\s]+\.bat',
                r'C:\\Windows\\Temp\\[^\s]+\.source\.ext\s+C:\\Windows\\Temp\\[^\s]+\.dest\.ext',
                r'\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.bat\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+\.bat'
            ],
            
            # explorer.exe patterns
            'explorer.exe': [
                r'/root,"?C:\\Windows\\Temp\\[^\s]+\.exe"?',
                r'^explorer\.exe\s+C:\\Windows\\Temp\\[^\s]+\.exe$'
            ],
            
            # Extexport.exe patterns
            'Extexport.exe': [
                r'C:\\Windows\\Temp\\[^\s]+(\s+\w+){1,2}'
            ],
            
            # extrac32.exe patterns
            'extrac32.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.cab\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+',
                r'/[Yy]\s+/[Cc]\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\s+C:\\Windows\\Temp\\[^\s]+',
                r'/[Cc]\s+C:\\Windows\\Temp\\[^\s]+\s+C:\\Windows\\Temp\\[^\s]+'
            ],
            
            # findstr.exe patterns
            'findstr.exe': [
                r'/V\s+/L\s+\w+\s+C:\\Windows\\Temp\\[^\s]+\s+>\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+',
                r'/S\s+/I\s+cpassword\s+\\\\sysvol\\policies\\\*\.xml',
                r'/V\s+/L\s+\w+\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\s+>\s+C:\\Windows\\Temp\\[^\s]+'
            ],
            
            # finger.exe patterns
            'finger.exe': [
                r'finger\s+\S+\s+\|\s+more\s+\+\d+\s+\|\s+cmd'
            ],
            
            # fltMC.exe patterns
            'fltMC.exe': [
                r'unload\s+\w+'
            ],
            
            # forfiles.exe patterns
            'forfiles.exe': [
                # Basic: forfiles with command execution using cmd.exe
                r'/c\s+"?cmd\s+/c\s+[^\s"]+"?',
                # Match for suspicious inline execution of known LOLBins (powershell, wscript, etc.)
                r'/c\s+"?(cmd|powershell|wscript|cscript|rundll32|mshta)(\.exe)?\s+/c\s+[^\s"]+"?',
                # Targeting specific extensions (commonly abused)
                r'/m\s+\*\.(exe|ps1|vbs|bat|cmd|js)',
                # Match combination of /p path + /c execution
                r'/p\s+[^\s]+\s+/m\s+\*\.[^\s]+\s+/c\s+"?cmd\s+/c\s+[^\s"]+"?'
                r'/p\s+c:\\windows\\system32\s+/m\s+\w+\.exe\s+/c\s+"cmd\s+/c\s+c:\\windows\\system32\\calc\.exe"',
                r'/p\s+c:\\windows\\system32\s+/m\s+\w+\.exe\s+/c\s+"C:\\Windows\\Temp\\[^\s]+:[^\s]+"'
            ],
            
            # fsutil.exe patterns
            'fsutil.exe': [
                r'file\s+setZeroData\s+offset=\d+\s+length=\d+\s+C:\\Windows\\Temp\\[^\s]+',
                r'usn\s+deletejournal\s+/d\s+c:',
                r'trace\s+decode'
            ],
            
            # ftp.exe patterns
            'ftp.exe': [
                r'echo\s+!cmd\s+/c\s+c:\\windows\\system32\\calc\.exe\s+>\s+ftpcommands\.txt\s+&&\s+ftp\s+-s:ftpcommands\.txt',
                r'cmd\.exe\s+/c\s+"@echo\s+open\s+[^\s]+\s+\d+>ftp\.txt.*ftp\s+-s:ftp\.txt\s+-v"'
            ],
            
            # Gpscript.exe patterns
            'Gpscript.exe': [
                r'/logon',
                r'/startup'
            ],
            
            # hh.exe patterns
            'hh.exe': [
                r'https?://[^\s]+\.bat',
                r'C:\\Windows\\Temp\\[^\s]+\.exe',
                r'https?://[^\s]+\.chm'
            ],
            
            # IMEWDBLD.exe patterns
            'IMEWDBLD.exe': [
                r'https?://[^\s]+'
            ],
            
            # ie4uinit.exe patterns
            'ie4uinit.exe': [
                r'-BaseSettings'
            ],
            
            # iediagcmd.exe patterns
            'iediagcmd.exe': [
                r'/out:C:\\Windows\\Temp\\[^\s]+\.cab'
            ],
            
            # ieexec.exe patterns
            'ieexec.exe': [
                r'https?://[^\s]+\.exe'
            ],
            
            # ilasm.exe patterns
            'ilasm.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.txt\s+/exe',
                r'C:\\Windows\\Temp\\[^\s]+\.txt\s+/dll'
            ],
            
            # InfDefaultInstall.exe patterns
            'InfDefaultInstall.exe': [
                r'[^\s]+\.inf'
            ],
            
            # InstallUtil.exe patterns
            'InstallUtil.exe': [
                r'/logfile=\s+/LogToConsole=false\s+/U\s+[^\s]+\.dll',
                r'https?://[^\s]+\.ext',
                r'/logfile=\s+/LogToConsole=false\s+/U\s+[^\s]+\.dll',
                r'/U\s+[^\s]+\.dll',  # Simpler variant if flags are missing
                r'/U\s+(?:[a-zA-Z]:)?\\[^\s]+\.dll',  # Absolute path DLL
                r'/logfile=[^\s]*\s+/U\s+[^\s]+\.dll',
                r'/logfile=\s+/U\s+[^\s]+\.dll'
            ],
            
            # jsc.exe patterns
            'jsc.exe': [
                r'[^\s]+\.js',
                r'/t:library\s+[^\s]+\.js'
            ],
            
            # ldifde.exe patterns
            'ldifde.exe': [
                r'-i\s+-f\s+[^\s]+\.ldf'
            ],
            
            # makecab.exe patterns
            'makecab.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.exe\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+\.cab',
                r'\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.exe\s+C:\\Windows\\Temp\\[^\s]+(:[^\s]+\.cab)?',
                r'/F\s+[^\s]+\.ddf'
            ],
            
            # mavinject.exe patterns
            'mavinject.exe': [
                r'\d+\s+/INJECTRUNNING\s+C:\\Windows\\Temp\\[^\s]+\.dll',
                r'\d+\s+/INJECTRUNNING\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+\.dll'
            ],
            
            # microsoft.workflow.compiler.exe patterns
            'microsoft.workflow.compiler.exe': [
                r'[^\s]+\s+[^\s]+\.log'
            ],
            
            # mmc.exe patterns
            'mmc.exe': [
                r'-Embedding\s+C:\\Windows\\Temp\\[^\s]+\.msc',
                r'gpedit\.msc'
            ],
            
            # mpcmdrun.exe patterns
            'mpcmdrun.exe': [
                r'-DownloadFile\s+-url\s+https?://[^\s]+\s+-path\s+C:\\Windows\\Temp\\[^\s]+',
                r'-DownloadFile\s+-url\s+https?://[^\s]+\s+-path\s+C:\\Users\\Public\\Downloads\\[^\s]+',
                r'-DownloadFile\s+-url\s+https?://[^\s]+\s+-path\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+',
                r'copy\s+".*?MpCmdRun\.exe"\s+C:\\Users\\Public\\Downloads\\MP\.exe\s+&&\s+chdir\s+".*?"\s+&&\s+".*?MP\.exe"\s+-DownloadFile\s+-url\s+https?://[^\s]+\s+-path\s+C:\\Users\\Public\\Downloads\\[^\s]+'
            ],
            
            # msbuild.exe patterns
            'msbuild.exe': [
                r'[^\s]+\.xml',
                r'[^\s]+\.csproj',
                r'/logger:TargetLogger,C:\\Windows\\Temp\\[^\s]+\.dll;MyParameters,[^\s]+',
                r'[^\s]+\.proj',
                r'@file\.rsp',
                 # Suspicious location for .proj files (e.g., dropped by malware)
                r'(AppData|Temp|\\Users\\[^\\]+\\Downloads)\\[^\s]+\.proj',
                # Inline C#/VB.NET code inside .proj files (if content is parsed)
                r'<Task\s+[^>]*>\s*<Code\s+[^>]*Language="(C#|VB)"\s*>'
            ],
            
            # msconfig.exe patterns
            'msconfig.exe': [
                r'-5'
            ],
            
            # msdt.exe patterns
            'msdt.exe': [
                r'-path\s+C:\\WINDOWS\\diagnostics\\index\\PCWDiagnostic\.xml\s+-af\s+C:\\Windows\\Temp\\[^\s]+\.xml\s+/skip\s+TRUE',
                r'/id\s+PCWDiagnostic\s+/skip\s+force\s+/param\s+".*?\$\([^\)]+\)\.exe"'
            ],
            
            # msedge.exe patterns
            'msedge.exe': [
                r'https?://[^\s]+\.exe\.txt',
                r'--headless\s+--enable-logging\s+--disable-gpu\s+--dump-dom\s+"https?://[^\s]+\.base64\.html"\s+>\s+[^\s]+\.b64',
                r'--disable-gpu-sandbox\s+--gpu-launcher="cmd\s+/c\s+c:\\windows\\system32\\[^\s]+\.exe\s+&&"'
            ],
            
            # mshta.exe patterns
            'mshta.exe': [
                    # Remote HTA execution
                    r'mshta\.exe\s+"?https?://[^\s"]+\.hta"?',
                    r'mshta(\.exe)?\s+((http|https|file):|["\']?javascript:)',
                    # Obfuscated JavaScript inline
                    r'javascript\s*:[\s\S]*document\.write',
            
                    # Embedded script protocol abuse (inline js or vbscript)
                    r'mshta\s+["\']?(javascript|vbscript):[^\s"\']+["\']?',
                    # Obfuscated script loading from remote SCT via VBScript
                    r'vbscript:Close\(Execute\("GetObject\("+"script:https?://[^\s"]+\.sct"\)\)\)',
                    r'javascript:a=GetObject\("script:https?://[^\s"]+\.sct"\)\.Exec\(\);close\(\);',
                    # Local HTA file execution
                    r'mshta\.exe\s+[a-zA-Z]:\\[^\s"]+\.hta',
                    # HTA files from suspicious folders
                    r'(AppData|Temp|\\Users\\[^\\]+\\Downloads)\\[^\s"]+\.hta',
                    # ADS-style HTA execution
                    r'C:\\Windows\\Temp\\[^\s]+:[^\s]+\.hta',
                    # Generic .hta execution (fallback catch-all)
                    r'[^\s"]+\.hta',
                    # Miscellaneous or typo-tolerant extensions
                    r'https?://[^\s"]+\.ext'
                ],  

            
            # msiexec.exe patterns
            'msiexec.exe': [
                r'/quiet\s+/i\s+[^\s]+\.msi',
                r'/q\s+/i\s+https?://[^\s]+\.ext',
                r'/[yz]\s+C:\\Windows\\Temp\\[^\s]+\.dll',
                r'/i\s+C:\\Windows\\Temp\\[^\s]+\.msi\s+TRANSFORMS="https?://[^\s]+\.mst"\s+/qb'
            ],
            
            # netsh.exe patterns
            'netsh.exe': [
                r'add\s+helper\s+C:\\Windows\\Temp\\[^\s]+\.dll',
                # DLL sideloading via add helper
                r'add\s+helper\s+[a-zA-Z]:\\[^\s]+\.dll',
                # Port proxy setup (commonly used in C2 traffic tunneling)
                r'interface\s+portproxy\s+add\s+v4tov4\s+listenport=\d+\s+connectaddress=[^\s]+\s+connectport=\d+',
                # Persistent firewall rule manipulation (evasion or backdoor)
                r'advfirewall\s+firewall\s+add\s+rule\s+name="[^"]*"\s+dir=in\s+action=allow\s+program="?[^\s"]+\.exe"?',
                # Remove firewall rule (evading detection or cleanup)
                r'advfirewall\s+firewall\s+delete\s+rule\s+name="[^"]+"',
                # Disable Windows firewall completely
                r'advfirewall\s+set\s+allprofiles\s+state\s+off',
                # Adding forwarding rules (used in pivoting/tunneling)
                r'interface\s+portproxy\s+add\s+v4tov4\s+.*',
                # General helper DLLs in temp locations (flexible pattern)
                r'add\s+helper\s+(AppData|Temp|\\Users\\[^\\]+\\Downloads)\\[^\s]+\.dll'
            ],
            
            # ngen.exe patterns
            'ngen.exe': [
                r'https?://[^\s]+\.ext'
            ],
            
            # odbcconf.exe patterns
            'odbcconf.exe': [
                r'/a\s+\{REGSVR\s+C:\\Windows\\Temp\\[^\s]+\.dll\}',
                r'INSTALLDRIVER\s+"[^|]+\|Driver=C:\\Windows\\Temp\\[^\s]+\.dll\|[^"]+"',
                r'configsysdsn\s+"[^"]+"\s+"DSN=[^"]+"',
                r'-f\s+[^\s]+\.rsp'
            ],
            
            # offlinescannershell.exe patterns
            'offlinescannershell.exe': [
                r'.*'
            ],
            
            # onedrivestandaloneupdater.exe patterns
            'onedrivestandaloneupdater.exe': [
                r'.*'
            ],
            
            # pcalua.exe patterns
            'pcalua.exe': [
                r'-a\s+[^\s]+\.exe',
                r'-a\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.dll',
                r'-a\s+C:\\Windows\\Temp\\[^\s]+\.cpl\s+-c\s+Java'
            ],
            
            # pcwrun.exe patterns
            'pcwrun.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.exe',
                r'/\.\./\.\./\$\([^\)]+\)\.exe'
            ],
            
            # pktmon.exe patterns
            'pktmon.exe': [
                r'start\s+--etw',
                r'filter\s+add\s+-p\s+445'
            ],
            
            # pnputil.exe patterns
            'pnputil.exe': [
                r'-i\s+-a\s+C:\\Windows\\Temp\\[^\s]+\.inf'
            ],
            
            # presentationhost.exe patterns
            'presentationhost.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.xbap',
                r'https?://[^\s]+'
            ],
            
            # print.exe patterns
            'print.exe': [
                r'/D:C:\\Windows\\Temp\\[^\s]+:[^\s]+\s+C:\\Windows\\Temp\\[^\s]+',
                r'/D:C:\\Windows\\Temp\\[^\s]+\.exe\s+C:\\Windows\\Temp\\[^\s]+\.exe',
                r'/D:C:\\Windows\\Temp\\[^\s]+\.exe\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.exe'
            ],
            
            # printbrm.exe patterns
            'printbrm.exe': [
                r'-b\s+-d\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\\?\s+-f\s+C:\\Windows\\Temp\\[^\s]+\.zip',
                r'-r\s+-f\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+\.zip\s+-d\s+C:\\Windows\\Temp\\[^\s]+'
            ],
            
            # provlaunch.exe patterns
            'provlaunch.exe': [
                r'LOLBin'
            ],
            
            # psr.exe patterns
            'psr.exe': [
                r'/start\s+/output\s+C:\\Windows\\Temp\\[^\s]+\.zip\s+/sc\s+\d+\s+/gui\s+\d+'
            ],
            
            # rasautou.exe patterns
            'rasautou.exe': [
                r'-d\s+[^\s]+\.dll\s+-p\s+[^\s]+\s+-a\s+[^\s]+\s+-e\s+[^\s]+'
            ],
            
            # rdrleakdiag.exe patterns
            'rdrleakdiag.exe': [
                r'/p\s+\d+\s+/o\s+C:\\Windows\\Temp\\[^\s]+\s+/fullmemdmp\s+/wait\s+\d+',
                r'/p\s+\d+\s+/o\s+C:\\Windows\\Temp\\[^\s]+\s+/fullmemdmp\s+/snap'
            ],
            
            # reg.exe patterns
            'reg.exe': [
                r'export\s+HKLM\\[^\s]+\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+\.reg',
                r'save\s+HKLM\\SECURITY\s+C:\\Windows\\Temp\\[^\s]+\.bak\s+&&\s+reg\s+save\s+HKLM\\SYSTEM\s+C:\\Windows\\Temp\\[^\s]+\.bak\s+&&\s+reg\s+save\s+HKLM\\SAM\s+C:\\Windows\\Temp\\[^\s]+\.bak'
            ],
            
            # regasm.exe patterns
            'regasm.exe': [
                r'[^\s]+\.dll',
                r'/U\s+[^\s]+\.dll'
            ],
            
            # regedit.exe patterns
            'regedit.exe': [
                r'/E\s+C:\\Windows\\Temp\\[^\s]+:[^\s]+\.reg\s+HKEY_CURRENT_USER\\[^\s]+',
                r'C:\\Windows\\Temp\\[^\s]+:[^\s]+\.reg'
            ],
            
            # regini.exe patterns
            'regini.exe': [
                r'[^\s]+:[^\s]+\.ini'
            ],
            
            # register-cimprovider patterns
            'register-cimprovider': [
                r'-path\s+C:\\Windows\\Temp\\[^\s]+\.dll'
            ],
            
            # regsvcs.exe patterns
            'regsvcs.exe': [
                r'[^\s]+\.dll'
            ],
            
            # regsvr32.exe patterns
            'regsvr32.exe': [
                # Basic HTTP-based SCT pattern (common LOLBin)
                r'/i:https?://[^\s]+\.sct\s+scrobj\.dll',
                        # With optional flags in any order (evasion attempts)
                r'(/s\s+)?(/n\s+)?(/u\s+)?/i:https?://[^\s]+\.sct\s+scrobj\.dll',
                r'(/n\s+)?(/s\s+)?(/u\s+)?/i:https?://[^\s]+\.sct\s+scrobj\.dll',
                r'(/u\s+)?(/n\s+)?(/s\s+)?/i:https?://[^\s]+\.sct\s+scrobj\.dll',
                        # File path SCT (local .sct dropped to disk)
                r'/i:file:///[^\s]+\.sct\s+scrobj\.dll',
                        # Non-standard / protocol-bypass tricks
                r'/i:(mshta|vbscript|jscript):[^\s]+',
                        # SCT followed by scrobj.dll with any flags
                r'/i:[^\s]+\.sct\s+scrobj\.dll',
                        # Any URL ending with .sct followed by scrobj.dll
                r'https?://[^\s]+\.sct\s+scrobj\.dll',
                        # Highly flexible fallback: any .sct and scrobj.dll in one line
                r'[^\s]+\.sct.*scrobj\.dll',
                r'/s\s+/n\s+/u\s+/i:https?://[^\s]+\.sct\s+scrobj\.dll',
                r'/s\s+/u\s+/i:[^\s]+\.sct\s+scrobj\.dll',
                r'regsvr32(\.exe)?\s+/s\s+/n\s+/u\s+/i\s+(http|https|file):'
            ],
            
            # replace.exe patterns
            'replace.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.cab\s+C:\\Windows\\Temp\\[^\s]+\\?\s+/A',
                r'\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.exe\s+C:\\Windows\\Temp\\[^\s]+\\?\s+/A'
            ],
            
            # rpcping.exe patterns
            'rpcping.exe': [
                r'-s\s+\d{1,3}(?:\.\d{1,3}){3}\s+-e\s+\d+\s+-a\s+\w+\s+-u\s+\w+',
                r'/s\s+\d{1,3}(?:\.\d{1,3}){3}\s+/e\s+\d+\s+/a\s+\w+\s+/u\s+\w+'
            ],
            
            # rundll32.exe patterns
            'rundll32.exe': [
                r'rundll32(\.exe)?\s+[\w\-.\\]+\.dll,\s*\w+',
                r'rundll32\s+.*,[\s\'+"]*[\w]{2,}',
                r'javascript:.*script:https?://',
                r'javascript:.*GetObject\("script:https?://',
                r'javascript:"\\\.\.\\mshtml,RunHTMLApplication"',
                r',ShOpenVerbApplication\s+https?://',
                r',InstallScreenSaver\s+\S+\.scr',
                r',RegisterOCX\s+\S+\.(dll|exe)',
                r'dfshim\.dll,ShOpenVerbApplication\s+https?://[^\s]+',
                r'[^\s]+,\w+',
                r'\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+,\w+',
                r'javascript:"\\\.\.\\mshtml,RunHTMLApplication\s+";.*GetObject\("script:https?://[^\s]+\.ext"\)',
                r'-sta\s+{[0-9a-fA-F\-]+}',
                r'"[^\s]+:[^\s]+\.dll",\w+',
                r'advpack\.dll,LaunchINFSection\s+[^\s,]+,DefaultInstall_SingleUser,1,',
                r'advpack\.dll,LaunchINFSection\s+[^\s,]+,,1,',
                r'advpack\.dll,RegisterOCX\s+[^\s]+',
                r'advpack\.dll,\s*RegisterOCX\s+cmd\s+/c\s+c:\\windows\\system32\\[^\s]+',
                r'desk\.cpl,InstallScreenSaver\s+(\\\\[^\s]+|[cC]:\\[^\s]+\.scr)',
                r'dfshim\.dll,ShOpenVerbApplication\s+https?://[^\s]+',
                r'ieadvpack\.dll,LaunchINFSection\s+[^\s,]+,DefaultInstall_SingleUser,1,',
                r'ieadvpack\.dll,LaunchINFSection\s+[^\s,]+,,1,',
                r'ieadvpack\.dll,RegisterOCX\s+[^\s]+',
                r'ieadvpack\.dll,\s*RegisterOCX\s+cmd\s+/c\s+c:\\windows\\system32\\[^\s]+',
                r'ieframe\.dll,OpenURL\s+[^\s]+\.url',
                r'mshtml\.dll,PrintHTML\s+[^\s]+\.hta',
                r'pcwutl\.dll,LaunchApplication\s+[^\s]+\.exe',
                r'scrobj\.dll,GenerateTypeLib\s+https?://[^\s]+',
                r'setupapi\.dll,InstallHinfSection\s+DefaultInstall\s+128\s+[^\s]+\.inf',
                r'shdocvw\.dll,OpenURL\s+[^\s]+\.url',
                r'shell32\.dll,Control_RunDLL\s+[^\s]+\.dll',
                r'shell32\.dll,ShellExec_RunDLL\s+[^\s]+\.exe',
                r'SHELL32\.DLL,ShellExec_RunDLL\s+[^\s]+\.exe(\s+/[^\s]+)*',
                r'shell32\.dll,#44\s+[^\s]+\.dll',
                r'shimgvw\.dll,ImageView_Fullscreen\s+https?://[^\s]+',
                r'syssetup\.dll,SetupInfObjectInstallAction\s+DefaultInstall\s+128\s+[^\s]+\.inf',
                r'url\.dll,OpenURL\s+[^\s]+\.hta',
                r'url\.dll,OpenURL\s+[^\s]+\.url',
                r'url\.dll,OpenURL\s+file://\^?[C]:/\^?W[^"]+',
                r'url\.dll,FileProtocolHandler\s+[^\s]+\.exe',
                r'url\.dll,FileProtocolHandler\s+file:///[^\s]+\.hta',
                r'zipfldr\.dll,RouteTheCall\s+[^\s]+\.exe',
                r'zipfldr\.dll,RouteTheCall\s+file://\^?C:/\^?W[^"]+',
                r'comsvcs\.dll\s+MiniDump\s+{[^\s]+}\s+[^\s]+\.bin\s+full'
            ],
            
            # runexehelper.exe patterns
            'runexehelper.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.exe'
            ],
            
            # runonce.exe patterns
            'runonce.exe': [
                r'/AlternateShellStartup'
            ],
            
            # runscripthelper.exe patterns
            'runscripthelper.exe': [
                r'surfacecheck\s+\\\\\?\\C:\\Windows\\Temp\\[^\s]+\.txt\s+C:\\Windows\\Temp\\[^\s]+'
            ],
            
            # sc.exe patterns
            'sc.exe': [
                r'create\s+[^\s]+\s+binPath="\\"c:\\ADS\\[^\s]+:[^\s]+\.exe\\".*"',
                r'config\s+{[^}]+}\s+binPath="\\"c:\\ADS\\[^\s]+:[^\s]+\.exe\\".*"\s+&\s+sc\s+start\s+{[^}]+}'
            ],
            
            # schtasks.exe patterns
            'schtasks.exe': [
                r'/create\s+/sc\s+minute\s+/mo\s+\d+\s+/tn\s+".*?"\s+/tr\s+"cmd\s+/c\s+c:\\windows\\system32\\[^\s]+"',
                r'/create\s+/s\s+[^\s]+\s+/tn\s+".*?"\s+/tr\s+"cmd\s+/c\s+c:\\windows\\system32\\[^\s]+"\s+/sc\s+daily',
                # Typical malicious task creation with embedded payload
                r'/create\s+/tn\s+[^\s]+\s+/tr\s+"?cmd\.exe\s+/c\s+[^\s"]+"?\s+/sc\s+onlogon',
                # General suspicious /create with any command in /tr
                r'/create\s+/tn\s+[^\s]+\s+/tr\s+"?[^\s]+\.exe(\s+[^\s"]+)*"?\s+/sc\s+\w+',
    
                   # More relaxed match for command line payloads
                r'/create\s+/tn\s+[^\s]+\s+/tr\s+"?.*?(powershell|cmd|wscript|cscript|mshta|rundll32).*"?',
    
                # Suspicious task triggers (logon, boot, unlock, etc.)
                r'/sc\s+(onlogon|onstart|onboot|onidle|onunlock)'
            ],
            
            # scriptrunner.exe patterns
            'scriptrunner.exe': [
                r'-appvscript\s+[^\s]+\.exe',
                r'-appvscript\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.cmd'
            ],
            
            # setres.exe patterns
            'setres.exe': [
                r'-w\s+\d+\s+-h\s+\d+'
            ],
            
            # settingsynchost.exe patterns
            'settingsynchost.exe': [
                r'-LoadAndRunDiagScript\s+[^\s]+\.exe',
                r'-LoadAndRunDiagScriptNoCab\s+[^\s]+\.bat'
            ],
            
            # sftp patterns
            'sftp': [
                r'-o\s+ProxyCommand="cmd\s+/c\s+c:\\windows\\system32\\[^\s]+"'
            ],
            
            # ssh patterns
            'ssh': [
                r'localhost\s+"cmd\s+/c\s+c:\\windows\\system32\\[^\s]+"',
                r'-o\s+ProxyCommand="cmd\s+/c\s+c:\\windows\\system32\\[^\s]+"\s+\.'
            ],
            
            # stordiag.exe patterns
            'stordiag.exe': [
                r'.*'
            ],
            
            # syncappvpublishingserver.exe patterns
            'syncappvpublishingserver.exe': [
                r'"n;\(New-Object\s+Net\.WebClient\)\.DownloadString\(\'https?://[^\']+\.ps1\'\)\s+\|\s+IEX"'
            ],
            
            # tar.exe patterns
            'tar.exe': [
                r'-cf\s+[^\s]+:[^\s]+\s+C:\\Windows\\Temp\\[^\s]+',
                r'-xf\s+[^\s]+:[^\s]+',
                r'-xf\s+\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s]+\.tar'
            ],
            
            # ttdinject.exe patterns
            'ttdinject.exe': [
                r'/ClientParams\s+"7\s+tmp\.run\s+0\s+0\s+0\s+0\s+0\s+0\s+0\s+0\s+0\s+0"\s+/Launch\s+"[^\s]+"',
                r'/ClientScenario\s+TTDRecorder\s+/ddload\s+\d+\s+/ClientParams\s+"7\s+tmp\.run\s+0\s+0\s+0\s+0\s+0\s+0\s+0\s+0\s+0\s+0"\s+/launch\s+"[^\s]+"'
            ],
            
            # tttracer.exe patterns
            'tttracer.exe': [
                r'C:\\Windows\\Temp\\[^\s]+\.exe',
                r'-dumpFull\s+-attach\s+\d+'
            ],
            
            # vbc.exe patterns
            'vbc.exe': [
                r'/target:exe\s+C:\\Windows\\Temp\\[^\s]+\.vb',
                r'-reference:Microsoft\.VisualBasic\.dll\s+C:\\Windows\\Temp\\[^\s]+\.vb'
            ],
            
            # verclsid.exe patterns
            'verclsid.exe': [
                r'/S\s+/C\s+{[^}]+}'
            ],
            
            # wab.exe patterns
            'wab.exe': [
                r'.*'
            ],
            
            # wbadmin.exe patterns
            'wbadmin.exe': [
                r'start\s+backup\s+-backupTarget:C:\\Windows\\Temp\\[^\s]+\s+-include:C:\\Windows\\NTDS\\NTDS\.dit,C:\\Windows\\System32\\config\\SYSTEM\s+-quiet',
                r'start\s+recovery\s+-version:\s+-recoverytarget:C:\\Windows\\Temp\\[^\s]+\s+-itemtype:file\s+-items:C:\\Windows\\NTDS\\NTDS\.dit,C:\\Windows\\System32\\config\\SYSTEM\s+-notRestoreAcl\s+-quiet'
            ],
            
            # wbemtest.exe patterns
            'wbemtest.exe': [
                r'.*'
            ],
            
            # winget.exe patterns
            'winget.exe': [
                r'install\s+--manifest\s+[^\s]+\.yml',
                r'install\s+--accept-package-agreements\s+-s\s+msstore\s+[^{}\s]+',
                r'install\s+--accept-package-agreements\s+-s\s+msstore\s+{[^}]+}'
            ],
            
            # wlrmdr.exe patterns
            'wlrmdr.exe': [
                r'-s\s+\d+\s+-f\s+\d+\s+-t\s+_\s+-m\s+_\s+-a\s+\d+\s+-u\s+[^\s]+\.exe'
            ],
            
            # wmic.exe patterns
            'wmic.exe': [
                r'process\s+call\s+create\s+"C:\\Windows\\Temp\\[^\s]+:program\.exe"',
                r'process\s+call\s+create\s+"cmd\s+/c\s+c:\\windows\\system32\\calc\.exe"',
                r'/node:"\d{1,3}(?:\.\d{1,3}){3}"\s+process\s+call\s+create\s+"cmd\s+/c\s+c:\\windows\\system32\\calc\.exe"',
                r'process\s+get\s+brief\s+/format:"https?://[^\s"]+\.xsl"',
                r'process\s+get\s+brief\s+/format:"\\\\servername\\C\$\\Windows\\Temp\\[^\s"]+\.xsl"',
                r'datafile\s+where\s+"Name=\'C:\\\\windows\\\\system32\\\\calc\.exe\'"\s+call\s+Copy\s+"C:\\\\users\\\\public\\\\calc\.exe"'
            ],
            
            # workfolders patterns
            'workfolders': [
                r'.*'
            ],
            
            # wscript.exe patterns
            'wscript.exe': [
                # Basic pattern: executing a .vbs file
                r'\s+[^\s]+\.vbs',
                # Suspicious command line with URLs (remote payloads)
                r'https?://[^\s]+\.vbs',
                # Any command line invoking scripts from common temp or user folders
                r'(AppData|Temp|\\Users\\[^\\]+\\Downloads)\\[^\s]+\.vbs',
                # Obfuscated script arguments (encoded, random names)
                r'[a-zA-Z]:\\[^\s]+\\[a-zA-Z0-9_]{5,}\.vbs',
                # Optional: detect double script use (wscript payload.vbs //B //Nologo)
                r'\.vbs(\s+//B)?(\s+//NoLogo)?'
                r'//e:vbscript\s+[^\s]+:script\.vbs',
                r'echo\s+GetObject\("script:https://[^\s"]+"\)\s+>\s+C:\\Windows\\Temp\\[^\s]+:hi\.js\s+&&\s+wscript\.exe\s+C:\\Windows\\Temp\\[^\s]+:hi\.js'
            ],
            
            # wsreset.exe patterns
            'wsreset.exe': [
                r'.*'
            ],
            
            # wuauclt.exe patterns
            'wuauclt.exe': [
                r'/UpdateDeploymentProvider\s+C:\\Windows\\Temp\\[^\s]+\.dll\s+/RunHandlerComServer'
            ],
            
            # xwizard.exe patterns
            'xwizard.exe': [
                r'RunWizard\s+{[0-9a-fA-F-]+}',
                r'RunWizard\s+/taero\s+/u\s+{[0-9a-fA-F-]+}',
                r'RunWizard\s+{[0-9a-fA-F-]+}\s+/zhttps?://[^\s"]+\.ext'
            ],
            
            # msedge_proxy.exe patterns
            'msedge_proxy.exe': [
                r'https?://[^\s"]+\.zip',
                r'--disable-gpu-sandbox\s+--gpu-launcher="?cmd\s+/c\s+[^\s"]+'
            ],
            
            # msedgewebview2.exe patterns
            'msedgewebview2.exe': [
                r'--no-sandbox\s+--browser-subprocess-path="?[^"\s]+\.exe"?',
                r'--utility-cmd-prefix="?cmd\s+/c\s+[^\s"]+"?',
                r'--disable-gpu-sandbox\s+--gpu-launcher="?cmd\s+/c\s+[^\s"]+"?',
                r'--no-sandbox\s+--renderer-cmd-prefix="?cmd\s+/c\s+[^\s"]+"?'
            ],
            
            # wt.exe patterns
            'wt.exe': [
                r'cmd\s+/c\s+c:\\windows\\system32\\[^\s"]+'
            ],
            
            # AccCheckConsole.exe patterns
            'AccCheckConsole.exe': [
                r'-window\s+".+?"\s+C:\\Windows\\Temp\\[^\s"]+\.dll'
            ],
            
            # adplus.exe patterns
            'adplus.exe': [
                r'-hang\s+-pn\s+[^\s]+\.exe\s+-o\s+C:\\Windows\\Temp\\[^\s]+(\s+-quiet)?',
                r'-c\s+[^\s]+\.xml',
                r'-crash\s+-o\s+"?C:\\Windows\\Temp\\[^\s"]+"?\s+-sc\s+[^\s]+\.exe'
            ],
            
            # AgentExecutor.exe patterns
            'AgentExecutor.exe': [
                r'-powershell\s+"C:\\Windows\\Temp\\[^\s"]+\.ps1"\s+"C:\\Windows\\Temp\\[^\s"]+\.log"\s+"C:\\Windows\\Temp\\[^\s"]+\.log"\s+"C:\\Windows\\Temp\\[^\s"]+\.log"\s+\d+\s+"(C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1\.0|C:\\Windows\\Temp\\[^\s"]+)"\s+0\s+1'
            ],
            
            # appcert.exe patterns
            'appcert.exe': [
                r'test\s+-apptype\s+desktop\s+-setuppath\s+C:\\Windows\\Temp\\[^\s"]+\.exe\s+-reportoutputpath\s+C:\\Windows\\Temp\\[^\s"]+\.xml',
                r'test\s+-apptype\s+desktop\s+-setuppath\s+C:\\Windows\\Temp\\[^\s"]+\.msi\s+-setupcommandline\s+/q\s+-reportoutputpath\s+C:\\Windows\\Temp\\[^\s"]+\.xml'
            ],
            
            # AppVLP.exe patterns
            'AppVLP.exe': [
                r'\\\\[^\s]+\\C\$\\Windows\\Temp\\[^\s"]+\.bat',
                r'powershell\.exe\s+-c\s+"\$e=New-Object\s+-ComObject\s+shell\.application;\$e\.ShellExecute\(\'[^\']+\.exe\',\'\',\s*\'\',\s*\'open\',\s*1\)"'
            ],
            
            # bginfo.exe patterns
            'bginfo.exe': [
                r'[^\s"]+\.bgi\s+/popup\s+/nolicprompt'
            ],
            
            # cdb.exe patterns
            'cdb.exe': [
                r'-cf\s+[^\s"]+\.wds\s+-o\s+[^\s"]+\.exe',
                r'-pd\s+-pn\s+{[^\s}]+}',
                r'\.shell\s+cmd\s+/c\s+c:\\windows\\system32\\[^\s"]+\.exe',
                r'-c\s+[^\s"]+\.txt\s+"cmd\s+/c\s+c:\\windows\\system32\\[^\s"]+\.exe"'
            ],
            
            # coregen.exe patterns
            'coregen.exe': [
                r'/L\s+C:\\Windows\\Temp\\[^\s"]+\.dll\s+[^\s"]+',
                r'[^\s"]+'
            ],
            
            # createdump.exe patterns
            'createdump.exe': [
                r'-n\s+-f\s+[^\s"]+\.dmp\s+\d+'
            ],
            
            # csi.exe patterns
            'csi.exe': [
                r'[^\s"]+\.cs'
            ],
            
            # DefaultPack.exe patterns
            'DefaultPack.exe': [
                r'/C:"cmd\s+/c\s+c:\\windows\\system32\\[^\s"]+\.exe"'
            ],
            
            # devinit.exe patterns
            'devinit.exe': [
                r'run\s+-t\s+msi-install\s+-i\s+https?://[^\s"]+\.msi'
            ],
            
            # devtoolslauncher.exe patterns
            'devtoolslauncher.exe': [
                r'LaunchForDeploy\s+C:\\Windows\\Temp\\[^\s"]+\.exe\s+".+?"\s+[^\s"]+',
                r'LaunchForDebug\s+C:\\Windows\\Temp\\[^\s"]+\.exe\s+".+?"\s+[^\s"]+'
            ],
            
            # dnx.exe patterns
            'dnx.exe': [
                r'C:\\Windows\\Temp\\[^\s"]+'
            ],
            
            # dotnet.exe patterns
            'dotnet.exe': [
                r'[^\s"]+\.dll',
                r'msbuild\s+[^\s"]+\.csproj',
                r'fsi'
            ],
            
            # dsdbutil.exe patterns
            'dsdbutil.exe': [
                r'"activate instance ntds"\s+"snapshot"\s+"create"\s+"quit"\s+"quit"',
                r'"activate instance ntds"\s+"snapshot"\s+"mount\s+{[0-9a-fA-F-]+}"\s+"quit"\s+"quit"',
                r'"activate instance ntds"\s+"snapshot"\s+"delete\s+{[0-9a-fA-F-]+}"\s+"quit"\s+"quit"',
                r'"activate instance ntds"\s+"snapshot"\s+"create"\s+"list all"\s+"mount\s+\d+"\s+"quit"\s+"quit"',
                r'"activate instance ntds"\s+"snapshot"\s+"list all"\s+"delete\s+\d+"\s+"quit"\s+"quit"'
            ],
            
            # dump64.exe patterns
            'dump64.exe': [
                r'\d+\s+[^\s"]+\.dmp'
            ],
            
            # DumpMinitool.exe patterns
            'DumpMinitool.exe': [
                r'--file\s+C:\\Windows\\Temp\\[^\s"]+\.\w+\s+--processId\s+\d+\s+--dumpType\s+Full'
            ],
            
            # Dxcap.exe patterns
            'Dxcap.exe': [
                r'-c\s+C:\\Windows\\Temp\\[^\s"]+\.exe'
            ],
            
            # ECMangen.exe patterns
            'ECMangen.exe': [
                r'https?://[^\s"]+'
            ],
            
            # Excel.exe patterns
            'Excel.exe': [
                r'https?://[^\s"]+'
            ],
            
            # fsi.exe patterns
            'fsi.exe': [
                r'[^\s"]+\.fsscript',
                r'$'
            ],
            
            # fsianycpu.exe patterns
            'fsianycpu.exe': [
                r'[^\s"]+\.fsscript',
                r'$'
            ],
            
            # Mftrace.exe patterns
            'Mftrace.exe': [
                r'[^\s"]+\.exe'
            ],
            
            # Microsoft.NodejsTools.PressAnyKey.exe patterns
            'Microsoft.NodejsTools.PressAnyKey.exe': [
                r'normal\s+\d+\s+[^\s"]+\.exe'
            ],
            
            # MSAccess.exe patterns
            'MSAccess.exe': [
                r'https?://[^\s"]+'
            ],
            
            # msdeploy.exe patterns
            'msdeploy.exe': [
                r'-verb:sync\s+-source:RunCommand\s+-dest:runCommand="C:\\Windows\\Temp\\[^\s"]+\.bat"',
                r'-verb:sync\s+-source:filePath=C:\\Windows\\Temp\\[^\s"]+\.\w+\s+-dest:filePath=C:\\Windows\\Temp\\[^\s"]+\.\w+'
            ],
            
            # MsoHtmEd.exe patterns
            'MsoHtmEd.exe': [
                r'https?://[^\s"]+'
            ],
            
            # mspub.exe patterns
            'mspub.exe': [
                r'https?://[^\s"]+'
            ],
            
            # msxsl.exe patterns
            'msxsl.exe': [
                r'[^\s"]+\.xml\s+[^\s"]+\.xsl',
                r'https?://[^\s"]+\.xml\s+https?://[^\s"]+\.xsl',
                r'https?://[^\s"]+\.xml\s+https?://[^\s"]+\.xsl\s+-o\s+[^\s"]+',
                r'https?://[^\s"]+\.xml\s+https?://[^\s"]+\.xsl\s+-o\s+[^\s"]+:[^\s"]+'
            ],
            
            # ntdsutil.exe patterns
            'ntdsutil.exe': [
                r'"ac i ntds"\s+"ifm"\s+"create full c:\\\\?"\s+q\s+q'
            ],
            
            # OpenConsole.exe patterns
            'OpenConsole.exe': [
                r'[^\s"]+\.exe'
            ],
            
            # Powerpnt.exe patterns
            'Powerpnt.exe': [
                r'https?://[^\s"]+'
            ],
            
            # procdump.exe patterns
            'procdump.exe': [
                r'-md\s+[^\s"]+\.dll\s+[^\s"]+'
            ],
            
            # ProtocolHandler.exe patterns
            'ProtocolHandler.exe': [
                r'https?://[^\s"]+'
            ],
            
            # rcsi.exe patterns
            'rcsi.exe': [
                r'[^\s"]+\.csx'
            ],
            
            # Remote.exe patterns
            'Remote.exe': [
                r'/s\s+\\\\?[^\s"]+\\[^\s"]+\\[^\s"]+\.exe\s+[^\s"]+',
                r'/s\s+[^\s"]+\.exe\s+[^\s"]+'
            ],
            
            # sqldumper.exe patterns
            'sqldumper.exe': [
                r'\d+\s+\d+\s+0x[0-9a-fA-F:]+'
            ],
            
            # Sqlps.exe patterns
            'Sqlps.exe': [
                r'-noprofile'
            ],
            
            # SQLToolsPS.exe patterns
            'SQLToolsPS.exe': [
                r'-noprofile\s+-command\s+Start-Process\s+[^\s"]+\.exe'
            ],
            
            # squirrel.exe patterns
            'squirrel.exe': [
                r'--download\s+https?://[^\s"]+',
                r'--update\s+https?://[^\s"]+',
                r'--updateRollback=https?://[^\s"]+'
            ],
            
            # te.exe patterns
            'te.exe': [
                r'[^\s"]+\.wsc',
                r'[^\s"]+\.dll'
            ],
            
            # teams.exe patterns
            'teams.exe': [
                r'--disable-gpu-sandbox\s+--gpu-launcher="cmd\s+/c\s+c:\\windows\\system32\\calc\.exe\s+&&?"'
            ],
            
            # TestWindowRemoteAgent.exe patterns
            'TestWindowRemoteAgent.exe': [
                r'start\s+-h\s+[a-zA-Z0-9+/=.-]+\.example\.com\s+-p\s+\d+'
            ],
            
            # Tracker.exe patterns
            'Tracker.exe': [
                r'/d\s+[^\s"]+\.dll\s+/c\s+C:\\Windows\\[^\s"]+\.exe'
            ],
            
            # Update.exe patterns
            'Update.exe': [
                r'--download\s+https?://[^\s"]+',
                r'--update\s*=\s*https?://[^\s"]+',
                r'--update\s*=\s*\\\\?[^\s"]+\\[^\s"]+',
                r'--updateRollback\s*=\s*https?://[^\s"]+',
                r'--updateRollback\s*=\s*\\\\?[^\s"]+\\[^\s"]+',
                r'--processStart\s+[^\s"]+\.exe\s+--process-start-args\s+"[^"]+"',
                r'--createShortcut\s*=\s*[^\s"]+\.exe\s+-l=Startup',
                r'--removeShortcut\s*=\s*[^\s"]+\.exe-l=Startup'
            ],
            
            # VSDiagnostics.exe patterns
            'VSDiagnostics.exe': [
                r'start\s+\d+\s+/launch:[^\s"]+\.exe',
                r'start\s+\d+\s+/launch:[^\s"]+\.exe\s+/launchArgs:"[^"]+"'
            ],
            
            # VSIISExeLauncher.exe patterns
            'VSIISExeLauncher.exe': [
                r'-p\s+[^\s"]+\.exe\s+-a\s+"[^"]+"'
            ],
            
            # Visio.exe patterns
            'Visio.exe': [
                r'https?://[^\s"]+'
            ],
            
            # VisualUiaVerifyNative.exe patterns
            'VisualUiaVerifyNative.exe': [
                r'.*'
            ],
            
            # VSLaunchBrowser.exe patterns
            'VSLaunchBrowser.exe': [
                r'\.exe\s+https?://[^\s"]+',
                r'\.exe\s+C:\\Windows\\Temp\\[^\s"]+\.exe',
                r'\.exe\s+\\\\[^\s"]+\\[^\s"]+'
            ],
            
            # vshadow.exe patterns
            'vshadow.exe': [
                r'-nw\s+-exec=[^\s"]+\.exe\s+C:'
            ],
            
            # Vsjitdebugger.exe patterns
            'Vsjitdebugger.exe': [
                r'[^\s"]+\.exe'
            ],
            
            # WFMFormat.exe patterns
            'WFMFormat.exe': [
                r'.*'
            ],
            
            # wfc.exe patterns
            'wfc.exe': [
                r'C:\\Windows\\Temp\\[^\s"]+\.xoml'
            ],
            
            # WinProj.exe patterns
            'WinProj.exe': [
                r'https?://[^\s"]+'
            ],
            
            # winword.exe patterns
            'winword.exe': [
                r'https?://[^\s"]+'
            ],
            
            # wsl.exe patterns
            'wsl.exe': [
                r'-e\s+/mnt/c/Windows/System32/[^\s"]+\.exe',
                r'-u\s+root\s+-e\s+cat\s+/etc/shadow',
                r'--exec\s+bash\s+-c\s+"cmd\s+/c\s+c:\\windows\\system32\\[^\s"]+\.exe"',
                r'--exec\s+bash\s+-c\s+\'cat\s+<\s+/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d{1,5}\s+>\s+[^\s\']+\''
            ],
            
            # xbootmgrsleep.exe patterns
            'xbootmgrsleep.exe': [
                r'\d+\s+"cmd\s+/c\s+c:\\windows\\system32\\[^\s"]+\.exe"'
            ],
            
            # devtunnel.exe patterns
            'devtunnel.exe': [
                r'host\s+-p\s+\d{1,5}'
            ],
            
            # vsls-agent.exe patterns
            'vsls-agent.exe': [
                r'--agentExtensionPath\s+C:\\Windows\\Temp\\[^\s"]+\.dll'
            ],
            
            # vstest.console.exe patterns
            'vstest.console.exe': [
                r'[^\s"]+\.dll'
            ],
            
            # winfile.exe patterns
            'winfile.exe': [
                r'[^\s"]+\.exe'
            ],
            
            # xsd.exe patterns
            'xsd.exe': [
                r'https?://[^\s"]+'
            ],
            
            # powershell.exe patterns
            'powershell.exe': [
                # Basic: Set-ItemProperty targeting HKCU Run key
                r'Set-ItemProperty\s+-Path\s+"?HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"?\s+-Name\s+"?[^\s"]+"?\s+-Value\s+"?[^\s"]+"?',
                # Optional variants with escaped backslashes or different casing
                r'Set-ItemProperty\s+-Path\s+"?HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"?\s+-Name\s+"?[^\s"]+"?\s+-Value\s+"?[^\s"]+"?',
                # Regex for New-ItemProperty variant
                r'New-ItemProperty\s+-Path\s+"?HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"?\s+-Name\s+"?[^\s"]+"?\s+-Value\s+"?[^\s"]+"?',
                # Match either HKCU or HKLM with Run/RunOnce keys
                r'(Set|New)-ItemProperty\s+-Path\s+"?HK(?:CU|LM):\\Software\\Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?"?\s+-Name\s+"?[^\s"]+"?\s+-Value\s+"?[^\s"]+"?'
                r'-ep\s+bypass\s+-command\s+"set-location.+?LoadAssemblyFromPath.+?\.dll;?\[Program\]::Fun\(\)"',
                r'-ep\s+bypass\s+-command\s+"set-location.+?RegSnapin.+?\.dll;?\[Program\.Class\]::Main\(\)"',
                r'-ep\s+bypass\s+-command\s+"[^"]*RegSnapin\s+[^\s"]+\.dll\s*;?\s*\[.*?\]::Main\(\)',
                r'import-module\s+[^\s"]*UtilityFunctions\.ps1'
                r"-EncodedCommand\s+[A-Za-z0-9+/=]{20,}",
                r"-enc\s+[A-Za-z0-9+/=]{20,}",
                r"-e\s+[A-Za-z0-9+/=]{20,}"

            ],
            
            # Launch-VsDevShell.ps1 patterns
            'Launch-VsDevShell.ps1': [
                r'-VsWherePath\s+C:\\Windows\\Temp\\[^\s"]+\.exe',
                r'-VsInstallationPath\s+".*file\.exe.*"'
            ],
            
            # SyncAppvPublishingServer.vbs patterns
            'SyncAppvPublishingServer.vbs': [
                r'"[^"]*DownloadString\(\s*\'https?:\/\/[^\s\']+\.ps1\'\s*\)\s*\|\s*IEX'
            ],
            
            # winrm patterns
            'winrm': [
                r'winrm\s+invoke\s+Create\s+wmicimv2/Win32_Process\s+\@{CommandLine\s*=\s*"cmd\s*/c\s+[^\s"]+\.exe"}',
                r'winrm\s+invoke\s+Create\s+wmicimv2/Win32_Service\s+\@{[^}]*PathName\s*=\s*"cmd\s*/c\s+[^\s"]+\.exe"}.*?StartService'
            ],
            
            # pubprn.vbs patterns
            'pubprn.vbs': [
                r'127\.0\.0\.1\s+script:https?:\/\/[^\s"]+\.sct'
            ],
            
            # Pester.bat patterns
            'Pester.bat': [
                r'\$null;\s*cmd\s*/c\s+[^\s"]+\.exe',
                r';\s*[^\s"]+\.exe'
            ]
       }
        return LOLBIN_PATTERNS

    def _load_whitelist_patterns(self):
        """Common legitimate uses to exclude"""
        WHITELIST_PATTERNS= {
           'certutil.exe': [
                r'-dump$',
                r'-viewstore$',
                r'-ping\s+',
                r'-verifyctl\s+-f\s+http://crl\.microsoft\.com',
                r'-urlcache\s+-split\s+http://ctldl\.windowsupdate\.com'
            ],
            'rundll32.exe': [
                r'Control_RunDLL\s+\w+\.cpl',
                r'Shell32\.dll,Control_RunDLL',
                r'ThemeUI\.dll,OpenThemeData'
            ],
            'powershell.exe': [
                r'-Command\s+Get-Process',
                r'-Command\s+Get-Service',
                r'-ExecutionPolicy\s+Restricted',
                r'-File\s+[A-Za-z]:\\Program\sFiles\\',
                # Base64-encoded commands
                r'-Enc(odedCommand)?\s+[A-Za-z0-9+/=]{20,}',
                # Obfuscated IEX (Invoke-Expression)
                r'i\s*[\'+"]?\s*e\s*[\'+"]?\s*x',  # i e x, i'e'x, i"+"e"+"x", etc.
                # Obfuscated Invoke-Expression
                r'(i[\'+"]?n[\'+"]?v[\'+"]?o[\'+"]?k[\'+"]?e[\'+"]?-?[\'+"]?e[\'+"]?x[\'+"]?p[\'+"]?r[\'+"]?e[\'+"]?s[\'+"]?s[\'+"]?i[\'+"]?o[\'+"]?n)',
                # Obfuscated download using Invoke-WebRequest / Net.WebClient
                r'(invoke[\'+"]?-[\'+"]?w[\'+"]?e[\'+"]?b[\'+"]?r[\'+"]?e[\'+"]?q[\'+"]?u[\'+"]?e[\'+"]?s[\'+"]?t)',
                r'new[\s\'+"]*-[\s\'+"]*object[\s\'+"]+net[\s\'+"]*\.[\s\'+"]*webclient',
                # Suspicious ExecutionPolicy bypass with obfuscation
                r'-e[\'+"]?x[\'+"]?e[\'+"]?c[\'+"]?u[\'+"]?t[\'+"]?i[\'+"]?o[\'+"]?n[\'+"]?p[\'+"]?o[\'+"]?l[\'+"]?i[\'+"]?c[\'+"]?y\s+[\'+"]?bypass',
                # Hidden character obfuscation (e.g., Unicode or ASCII codes)
                r'(Invoke|IEX|DownloadString|FromBase64String|Shellcode)[\x00-\x20]+'
            ],
            'bitsadmin.exe': [
                r'/transfer\s+WindowsUpdate',
                r'/create\s+WindowsUpdate',
                r'/addfile\s+http://windowsupdate\.com'
            ],
            'msiexec.exe': [
                r'/i\s+[A-Za-z]:\\Program\sFiles\\',
                r'/package\s+[A-Za-z]:\\Program\sFiles\\',
                r'/quiet\s+/i\s+http://windowsupdate\.com'
            ],
            'wmic.exe': [
                r'process\s+get\s+name',
                r'os\s+get\s+caption',
                r'/node:localhost\s+process\s+list\s+brief'
            ],
            'msbuild.exe': [
                # Basic execution of a .proj or .targets file
                r'\s+[^\s]+\.(proj|targets)',
                # Match common suspicious directory paths (temp, downloads, etc.)
                r'(AppData|Temp|\\Users\\[^\\]+\\Downloads)\\[^\s]+\.(proj|targets)',
                # Execution of known malicious MSBuild inline tasks (C#, base64, etc.)
                r'<Task\s+.*?Code\s*=\s*".*?(base64|System\.Reflection|System\.Diagnostics)',
                # Encoded or obfuscated inline C# code pattern inside a proj file
                r'(System\.IO|System\.Net|System\.Diagnostics|FromBase64String)'
                # Match optional quiet flags
                r'/nologo\s+/verbosity:(quiet|minimal)'
                r'/t:Restore',
                r'/t:Rebuild',
                r'/p:Configuration=Release'
            ],
            'wsl.exe': [
                r'--install',
                r'-d\s+Ubuntu',
                r'exec\s+/usr/bin/apt'
            ]
        }
        return WHITELIST_PATTERNS

    def _compile_patterns(self, patterns_dict):
        """Compile single combined regex per binary for O(1) matching"""
        combined = {}
        for binary, patterns in patterns_dict.items():
            try:
                combined_pattern = "|".join(f"({p})" for p in patterns)
                combined[binary.lower()] = re.compile(combined_pattern, re.IGNORECASE)
            except re.error as e:
                self.logger.error(f"Invalid pattern for {binary}: {str(e)}")
        return combined

    def _create_severity_map(self):
        """Create severity mapping for different LOLBins"""
        severity_map = {
            'powershell.exe': 'high',  # Keep as high severity for aggressive detection
            'cmd.exe': 'medium',
            'rundll32.exe': 'high',
            'regsvr32.exe': 'high',
            'msbuild.exe': 'high',
            'msiexec.exe': 'medium',
            'certutil.exe': 'high',
            'bitsadmin.exe': 'medium',
            'wmic.exe': 'medium',
            'wsl.exe': 'high',
            'winrm.exe': 'high',
            'pubprn.vbs': 'high',
            'SyncAppvPublishingServer.vbs': 'high',
            'Launch-VsDevShell.ps1': 'high',
            'Pester.bat': 'high'
        }
        return severity_map

    def detect(self, process_name, command_line):
        # Defensive: Ensure process_name and command_line are strings
        process_name = str(process_name) if process_name else ''
        command_line = str(command_line) if command_line else ''
        
        # Check cache first
        cache_key = f"{process_name}:{command_line}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        detected = False
        matched_pattern = None
        severity = 'low'  # Default to low if not in severity_map
        
        process_lower = process_name.lower()
        # Only check binaries in the severity map for speed
        if process_lower in self.severity_map and process_lower in self.malicious_combined:
            try:
                # Check if command line matches any LOLBin pattern
                if self.malicious_combined[process_lower].search(command_line):
                    # Check if it's whitelisted
                    if process_lower in self.whitelist_combined:
                        if self.whitelist_combined[process_lower].search(command_line):
                            # Whitelisted - not detected
                            result = {'detected': False, 'matched_pattern': None, 'severity': 'low'}
                            self.cache[cache_key] = result
                            return result
                    
                    # Not whitelisted - detected
                    detected = True
                    matched_pattern = f"LOLBin pattern for {process_name}"
                    severity = self.severity_map.get(process_lower, 'medium')
            except Exception as e:
                import logging
                logging.error(f"Error in LOLBin detection for {process_name}: {e}")
        
        result = {'detected': detected, 'matched_pattern': matched_pattern, 'severity': severity} if detected else {'detected': False}
        
        # Cache the result
        if len(self.cache) >= self.cache_size:
            # Remove oldest entry
            self.cache.pop(next(iter(self.cache)))
        self.cache[cache_key] = result
        
        return result

    def flush_cache(self):
        self.cache.clear()