"""
Enhanced Volt Typhoon Detector
Specialized detection for Volt Typhoon TTPs
"""

import re
import logging
from datetime import datetime

class EnhancedVoltTyphoonDetector:
    def __init__(self):
        # Volt Typhoon specific command patterns
        self.volt_typhoon_patterns = {
            # Network reconnaissance and pivoting
            'network_recon': [
                r'netsh\s+interface\s+portproxy\s+add',
                r'netsh\s+interface\s+portproxy\s+set',
                r'netsh\s+advfirewall\s+firewall\s+add\s+rule',
                r'netsh\s+wlan\s+show\s+profile',
                r'arp\s+-a',
                r'ipconfig\s+/all',
                r'route\s+print',
                r'nbtstat\s+-n',
            ],
            
            # Credential access and lateral movement
            'credential_access': [
                r'nltest\s+/domain_trusts',
                r'nltest\s+/dclist',
                r'net\s+group\s+"domain\s+admins"',
                r'net\s+user\s+/domain',
                r'net\s+accounts\s+/domain',
                r'dsquery\s+user',
                r'dsquery\s+computer',
                r'dsquery\s+group',
                r'net\s+localgroup\s+administrators',
                r'net\s+group\s+"domain\s+controllers"',
                r'net\s+group\s+"enterprise\s+admins"'
            ],
            
            # Persistence mechanisms
            'persistence': [
                r'schtasks\s+/create.*?/sc\s+onlogon',
                r'schtasks\s+/create.*?/ru\s+system',
                r'sc\s+create.*?binpath.*?cmd',
                r'reg\s+add.*?\\run\\',
                r'reg\s+add.*?\\services\\',
                r'wmic\s+service\s+call\s+create',
            ],
            
            # Defense evasion
            'defense_evasion': [
                r'powershell.*?-windowstyle\s+hidden',
                r'powershell.*?-executionpolicy\s+bypass',
                r'powershell.*?-encodedcommand',
                r'certutil.*?-urlcache.*?-split.*?-f',
                r'bitsadmin\s+/transfer',
                r'regsvr32\s+/s\s+/n\s+/u\s+/i:',
                r'mshta\s+vbscript:',
                r'rundll32\s+javascript:',
                r'powershell.*?-nop',
                r'powershell.*?-noexit',
                r'powershell.*?-noni',
                r'powershell.*?-ep\s+bypass',
                r'wmic.*?process.*?call.*?create',
                r'wmic.*?/node:.*?/user:.*?/password:',
                r'vssadmin\s+delete\s+shadows',
                r'bcdedit\s+/set\s+safeboot',
                r'attrib\s+\+s\s+\+h',
                r'icacls\s+.*?/grant',
                r'wevtutil\s+cl\s+system',
                r'wevtutil\s+cl\s+security',
                r'wevtutil\s+cl\s+application',
                r'fsutil\s+usn\s+deletejournal',
                r'net\s+stop\s+\w+',
                r'net\s+start\s+\w+',
                r'certutil.*?encode',
                r'findstr.*?\/V.*?\-',
                r'bitsadmin.*?\/transfer',
                r'curl.*?\-X\s+POST',
                r'schtasks.*?\\Microsoft\\Windows\\Diagnosis',
                r'wevtutil.*?qe.*?EventID\=4624'
            ],
            
            # Discovery and enumeration
            'discovery': [
                r'tasklist\s+/svc',
                r'whoami\s+/all',
                r'whoami\s+/groups',
                r'systeminfo',
                r'wmic\s+computersystem\s+get',
                r'wmic\s+process\s+list\s+full',
                r'net\s+localgroup\s+administrators',
                r'quser',
                r'query\s+session',
                r'net\s+view',
                r'net\s+user',
                r'net\s+group',
                r'net\s+share',
                r'arp\s+-a',
                r'ipconfig\s+/all',
                r'route\s+print',
                r'nbtstat\s+-a',
                r'nbtstat\s+-n',
                r'nbtstat\s+-s',
            ],
            
            # Data exfiltration preparation
            'collection': [
                r'forfiles.*?/m\s+\*\..*?/c\s+"cmd\s+/c',
                r'findstr.*?/s.*?/i.*?password',
                r'dir.*?/s.*?\*\.txt',
                r'copy.*?\\\\.*?\\c\$',
                r'xcopy.*?/s.*?/h.*?/e',
                r'robocopy.*?/mir',
                r'copy\s+.*?\\\\.*?\\admin\$',
                r'copy\s+.*?\\\\.*?\\c\$',
                r'robocopy\s+.*?\\\\.*?\\c\$',
                r'rar\.exe\s+a\s+.*?\.rar',
                r'7z\.exe\s+a\s+.*?\.7z',
                r'winrar\.exe\s+a\s+.*?\.zip',
            ]
        }
        
        self.ransomware_patterns = {
            'file_encryption': [
                r'crypt', r'encrypt', r'decrypt', r'aes', r'rsa', r'des', 
                r'\.locked', r'\.encrypted', r'\.crypted', r'\.ransom',
                r'vssadmin\s+delete\s+shadows',  # Shadow copy deletion
                r'wbadmin\s+delete\s+catalog',    # Backup catalog deletion
                r'fsutil\s+usn\s+deletejournal',   # USN journal deletion
                r'cipher\s+/w',                    # Secure delete
                r'forfiles.*?\.(docx|pdf|xlsx).*?/c\s+"cmd\s+/c\s+del'  # Mass file deletion
            ],
            'ransom_note_patterns': [
                r'readme\.txt', r'how_to_decrypt\.html', r'_restore_instructions_',
                r'!!!_warning_!!!', r'your_files_are_encrypted'
            ],
            'ransomware_process_chains': [
                ('explorer.exe', 'cmd.exe', 'cipher.exe'),
                ('svchost.exe', 'powershell.exe', 'certutil.exe'),
                ('services.exe', 'wmic.exe', 'vssadmin.exe')
            ]
        }
        
        # Suspicious process chains specific to Volt Typhoon
        self.volt_process_chains = [
            ('explorer.exe', 'cmd.exe', 'netsh.exe'),
            ('winlogon.exe', 'cmd.exe', 'nltest.exe'),
            ('services.exe', 'svchost.exe', 'powershell.exe'),
            ('lsass.exe', 'cmd.exe', 'tasklist.exe'),
            ('spoolsv.exe', 'cmd.exe', 'sc.exe'),
            ('svchost.exe', 'cmd.exe', 'reg.exe'),
            ('explorer.exe', 'wscript.exe', 'cscript.exe'),
            ('services.exe', 'cmd.exe', 'schtasks.exe')
        ]
        
        # Network indicators
        self.suspicious_network_patterns = [
            r'(\d{1,3}\.){3}\d{1,3}:443',  # Suspicious HTTPS connections
            r'(\d{1,3}\.){3}\d{1,3}:80',   # Suspicious HTTP connections
            r'tunnel|proxy|socks',          # Tunneling keywords
        ]

    def analyze_for_volt_typhoon(self, process_info, command_line):
        """Enhanced analysis specifically for Volt Typhoon TTPs"""
        risk_score = 0.0
        detected_patterns = []
        
        cmd_lower = command_line.lower()
        process_name = process_info.get('name', '').lower()
        
        # Check for Volt Typhoon command patterns
        for category, patterns in self.volt_typhoon_patterns.items():
            for pattern in patterns:
                if isinstance(pattern, (list, tuple)):
                    for p in pattern:
                        if re.search(p, command_line, re.IGNORECASE):
                            risk_score += 3.0
                            detected_patterns.append({
                                'category': category,
                                'pattern': p,
                                'severity': 'HIGH'
                            })
                else:
                    if re.search(pattern, command_line, re.IGNORECASE):
                        risk_score += 3.0
                        detected_patterns.append({
                            'category': category,
                            'pattern': pattern,
                            'severity': 'HIGH'
                        })
        
        # Check for suspicious timing (Volt Typhoon often operates during off-hours)
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 22:  # Between 10 PM and 6 AM
            risk_score += 1.0
            detected_patterns.append({
                'category': 'timing',
                'pattern': 'off_hours_activity',
                'severity': 'MEDIUM'
            })
        
        # Check for multiple LOLBins in single command
        lolbin_count = sum(1 for lolbin in self.get_extended_lolbins() 
                          if lolbin in cmd_lower)
        if lolbin_count > 2:
            risk_score += 2.0
            detected_patterns.append({
                'category': 'lolbin_chaining',
                'pattern': f'{lolbin_count}_lolbins_detected',
                'severity': 'HIGH'
            })
        
        # Check for base64 encoded PowerShell (common in Volt Typhoon)
        if 'powershell' in process_name:
            b64_patterns = [
                r'[A-Za-z0-9+/]{50,}={0,2}',  # Base64
                r'-enc.*?[A-Za-z0-9+/]{20,}',  # Encoded command
                r'frombase64string',           # Base64 decoding
                r'convert::frombase64string'   # .NET Base64 decoding
            ]
            for pattern in b64_patterns:
                if isinstance(pattern, (list, tuple)):
                    for p in pattern:
                        if re.search(p, command_line, re.IGNORECASE):
                            risk_score += 2.5
                            detected_patterns.append({
                                'category': 'obfuscation',
                                'pattern': 'base64_encoding',
                                'severity': 'HIGH'
                            })
                            break
                else:
                    if re.search(pattern, command_line, re.IGNORECASE):
                        risk_score += 2.5
                        detected_patterns.append({
                            'category': 'obfuscation',
                            'pattern': 'base64_encoding',
                            'severity': 'HIGH'
                        })
                        break
        
        # Check for command chaining
        if re.search(r'(&&|\|\||;){2,}', command_line):
            risk_score += 1.5
            detected_patterns.append({
                'category': 'chaining',
                'pattern': 'multiple_command_chaining',
                'severity': 'MEDIUM'
            })
            
        if not isinstance(process_info, dict):
            logging.error(f"Expected dict, got {type(process_info)}: {process_info}")
            return {
                'volt_typhoon_risk_score': 0.0,
                'detected_patterns': [],
                'is_volt_typhoon_like': False
            }    
        
        # Check for hex encoding
        if re.search(r'(0x[0-9a-fA-F]{2,}){4,}', command_line):
            risk_score += 1.5
            detected_patterns.append({
                'category': 'obfuscation',
                'pattern': 'hex_encoding',
                'severity': 'HIGH'
            })
        
        return {
            'volt_typhoon_risk_score': min(risk_score, 10.0),
            'detected_patterns': detected_patterns,
            'is_volt_typhoon_like': risk_score >= 3.0
        }
        
    def get_extended_lolbins(self):
        """Extended LOLBins list including recent additions"""
        return [
            # Original list
            'cmd.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe',
            'regsvr32.exe', 'rundll32.exe', 'forfiles.exe', 'debug.exe',
            'certutil.exe', 'bitsadmin.exe', 'netsh.exe', 'schtasks.exe',
            'tasklist.exe', 'sc.exe', 'whoami.exe', 'net.exe', 'nltest.exe', 
            'msiexec.exe', 'hh.exe', 'ieexec.exe', 'installutil.exe', 'msxsl.exe',
            'dnscmd.exe', 'diskshadow.exe', 'makecab.exe', 'expand.exe',
            'xwizard.exe', 'cmstp.exe', 'scriptrunner.exe', 'msdt.exe',
            'forfiles.exe', 'reg.exe', 'regedit.exe', 'regedt32.exe',
            
            # Additional LOLBins frequently used by Volt Typhoon
            'wbemtest.exe', 'odbcconf.exe', 'regasm.exe', 'regsvcs.exe',
            'installutil.exe', 'msbuild.exe', 'csi.exe', 'rcsi.exe',
            'winrm.vbs', 'slmgr.vbs', 'pubprn.vbs', 'syncappvpublishingserver.vbs',
            'pnputil.exe', 'fltmc.exe', 'relog.exe', 'wusa.exe',
            'esentutl.exe', 'vsjitdebugger.exe', 'sqldumper.exe',
            'sqlps.exe', 'dtexec.exe', 'dnscmd.exe', 'dsacls.exe',
            'ldifde.exe', 'csvde.exe', 'adplus.exe', 'appvlp.exe',
            
            # Additional high-risk LOLBins
            'msbuild.exe', 'installutil.exe', 'regasm.exe', 'regsvcs.exe',
            'msiexec.exe', 'cmstp.exe', 'control.exe'
        ] 