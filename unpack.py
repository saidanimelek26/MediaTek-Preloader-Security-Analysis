#!/usr/bin/env python3
import struct
import re
import os
import sys

class MediaTekPreloaderAnalyzer:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.data = None
        self.strings = []
        self.load_file()
    
    def load_file(self):
        with open(self.file_path, 'rb') as f:
            self.data = f.read()
        print(f"[+] Loaded {len(self.data)} bytes")
    
    def extract_strings(self):
        self.strings = []
        pattern = re.compile(b'[ -~]{4,}')
        for match in pattern.finditer(self.data):
            try:
                s = match.group().decode('ascii', errors='ignore')
                if len(s) > 3:
                    self.strings.append(s.lower())
            except:
                pass
    
    def security_analysis(self):
        results = {}
        
        secure_boot = False
        sbc_enabled = False
        for s in self.strings:
            if 'secure_boot' in s:
                secure_boot = True
            if 'sbc_en' in s or 'sboot' in s:
                sbc_enabled = True
        
        results["Secure Boot"] = secure_boot or sbc_enabled
        
        rpmb_found = False
        for s in self.strings:
            if 'rpmb' in s:
                rpmb_found = True
                if 'key' in s or 'auth' in s:
                    rpmb_found = "Key Protected"
        results["RPMB"] = rpmb_found
        
        trustzone_found = False
        tz_features = []
        for s in self.strings:
            if 'trustzone' in s or 'tz_' in s or 'tz-' in s:
                trustzone_found = True
                if 'enable' in s:
                    tz_features.append("Enabled")
                if 'secure' in s:
                    tz_features.append("Secure World")
                if 'normal' in s:
                    tz_features.append("Normal World")
        results["TrustZone"] = trustzone_found
        if tz_features:
            results["TrustZone Details"] = tz_features
        
        auth_found = False
        auth_methods = []
        for s in self.strings:
            if 'img_auth' in s or 'image_auth' in s:
                auth_found = True
            if 'verify' in s:
                if 'signature' in s:
                    auth_methods.append("Signature")
                if 'hash' in s:
                    auth_methods.append("Hash")
                if 'cert' in s:
                    auth_methods.append("Certificate")
        results["Image Authentication"] = auth_found
        if auth_methods:
            results["Auth Method"] = auth_methods
        
        debug_detected = []
        for s in self.strings:
            if 'debug' in s:
                if 'port' in s or 'uart' in s:
                    debug_detected.append("UART Debug")
                if 'usb' in s:
                    debug_detected.append("USB Debug")
                if 'jtag' in s:
                    debug_detected.append("JTAG")
                if 'disable' not in s and 'off' not in s:
                    debug_detected.append("Potentially Active")
        
        if debug_detected:
            results["Debug Interfaces"] = list(set(debug_detected))
        
        anti_rollback = False
        for s in self.strings:
            if 'anti_rollback' in s or 'rollback' in s:
                anti_rollback = True
                if 'counter' in s:
                    anti_rollback = "Counter Protected"
        results["Anti-Rollback"] = anti_rollback
        
        return results
    
    def check_vulnerable_patterns(self):
        vulns = []
        
        known_vulns = {
            'mtk_uart': 'UART Debug',
            'download_agent': 'Download Agent Exposure',
            'bootrom': 'BootROM Exploit Possible',
            'da_disable': 'Download Agent Not Secured',
            'sec_debug': 'Security Debug Enabled',
            'mtk_secure': 'MTK Security Patch Missing',
            'usbdl': 'USB Download Mode'
        }
        
        for s in self.strings:
            for pattern, vuln_name in known_vulns.items():
                if pattern in s:
                    vulns.append(vuln_name)
        
        if len(self.data) < 0x10000:
            vulns.append("Small File Size")
        
        null_bytes = self.data.count(b'\x00')
        if null_bytes > len(self.data) * 0.7:
            vulns.append("High Null Ratio")
        
        return list(set(vulns))
    
    def analyze_memory_protection(self):
        protections = []
        
        for s in self.strings:
            if 'mmu' in s or 'mmu_enable' in s:
                protections.append("MMU Enabled")
            if 'mpu' in s:
                protections.append("MPU Found")
            if 'dram_sec' in s or 'dram_security' in s:
                protections.append("DRAM Protection")
            if 'region_lock' in s:
                protections.append("Region Locking")
        
        return protections
    
    def run(self):
        print("=" * 70)
        print("MTK PRELOADER SECURITY ANALYZER")
        print("=" * 70)
        
        self.extract_strings()
        
        print(f"\n[1] File Information")
        print(f"    Size: {len(self.data)} bytes ({len(self.data)/1024:.2f} KB)")
        print(f"    Strings extracted: {len(self.strings)}")
        
        print(f"\n[2] Security Features")
        security = self.security_analysis()
        for feature, status in security.items():
            if isinstance(status, list):
                print(f"    {feature}: {', '.join(status)}")
            else:
                print(f"    {feature}: {'ENABLED' if status else 'NOT FOUND'}")
        
        print(f"\n[3] Memory Protection")
        mem_prot = self.analyze_memory_protection()
        if mem_prot:
            for prot in mem_prot:
                print(f"    {prot}")
        else:
            print("    No memory protection detected")
        
        print(f"\n[4] Vulnerability Check")
        vulns = self.check_vulnerable_patterns()
        if vulns:
            for vuln in vulns:
                print(f"    [!] {vuln}")
        else:
            print("    No known patterns found")
        
        print("\n" + "=" * 70)
        print("ANALYSIS COMPLETE")
        print("=" * 70)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 mtk_sec.py <preloader.bin>")
        print("Example: python3 mtk_sec.py preloader.bin")
        sys.exit(1)
    
    if not os.path.exists(sys.argv[1]):
        print(f"[-] File not found: {sys.argv[1]}")
        sys.exit(1)
    
    analyzer = MediaTekPreloaderAnalyzer(sys.argv[1])
    analyzer.run()

if __name__ == "__main__":
    main()