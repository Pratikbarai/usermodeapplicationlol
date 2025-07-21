import sys
import os
import json
import re

# Import detectors
from detection.lolbin_pattern_detector import LOLBinPatternDetector
from detection.volt_typhoon_detector import EnhancedVoltTyphoonDetector

# Initialize detectors
lolbin_detector = LOLBinPatternDetector()
volt_detector = EnhancedVoltTyphoonDetector()

def is_obfuscated(command_line):
    # Check for encoded command flags
    if re.search(r'-e(ncodedcommand)?\\b', command_line, re.IGNORECASE):
        return True
    # Check for suspicious string concatenation
    if re.search(r"['\"]\\s*\\+\\s*['\"]", command_line):
        return True
    # Check for chr/char/Invoke-Expression/iex
    if re.search(r'(chr|char|Invoke-Expression|iex)\\b', command_line, re.IGNORECASE):
        return True
    # Check for hex/unicode escapes
    if re.search(r'\\x[0-9a-fA-F]{2,}', command_line) or re.search(r'\\u[0-9a-fA-F]{4,}', command_line):
        return True
    # Check for excessive whitespace or mixed case in flags
    if re.search(r'-[a-zA-Z]\\s+[a-zA-Z]', command_line):
        return True
    return False

def classify_command(process_id, application_name, command_line_argument):
    # Obfuscation detection
    if is_obfuscated(command_line_argument):
        return 'obfuscated'
    # Check for LOLBin
    is_lolbin, lolbin_pattern = lolbin_detector.detect(application_name, command_line_argument)
    if is_lolbin:
        return 'lolbin'
    # Check for Volt Typhoon
    process_info = {'pid': process_id, 'name': application_name, 'cmdline': command_line_argument}
    volt_result = volt_detector.analyze_for_volt_typhoon(process_info, command_line_argument)
    if volt_result.get('is_volt_typhoon_like'):
        return 'volt_typhoon'
    return 'normal'

def main():
    if len(sys.argv) < 4:
        print("Usage: analyze.py <process_id> <application_name> <command_line_argument>", file=sys.stderr)
        sys.exit(2)
    process_id = sys.argv[1]
    application_name = sys.argv[2]
    command_line_argument = sys.argv[3]

    try:
        category = classify_command(process_id, application_name, command_line_argument)
        print(category)
        if category in ('lolbin', 'volt_typhoon', 'obfuscated'):
            sys.exit(1)  # 1 for malicious
        else:
            sys.exit(0)  # 0 for normal
    except Exception as e:
        print(f"Error during analysis: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main() 