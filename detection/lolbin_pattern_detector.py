"""
LOLBin Pattern Detector
Pattern-based detection for LOLBin abuse
"""

from lolbin_detector import LOLBinDetector

class LOLBinPatternDetector:
    def __init__(self):
        # Use the existing LOLBinDetector instead of importing undefined patterns
        self.lolbin_detector = LOLBinDetector()

    def detect(self, process_name, command_line):
        # Delegate to the existing LOLBinDetector
        result = self.lolbin_detector.detect(process_name, command_line)
        if result and result.get('detected'):
            return True, result.get('matched_pattern')
        return False, None 