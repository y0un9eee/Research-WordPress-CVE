#!/usr/bin/env python3
"""
Advanced WordPress Plugin Security Scanner
더 정교한 취약점 탐지를 위한 고급 스캐너
"""

import os
import re
import json
import time
import hashlib
import zipfile
import requests
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

@dataclass
class VulnerabilityReport:
    """취약점 보고서 데이터 구조"""
    plugin_name: str
    file_path: str
    line_number: int
    vulnerability_type: str
    severity: str
    code_snippet: str
    description: str
    recommendation: str
    context: str
    confidence: int  # 1-100
    timestamp: str

@dataclass
class PluginInfo:
    """플러그인 메타데이터"""
    name: str
    version: str
    last_updated: str
    active_installations: int
    url: str
    tested_wp_version: str

class SecurityScanner:
    """고급 보안 스캐너 클래스"""
    
    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)
        self.results_dir = self.base_dir / "security_results"
        self.results_dir.mkdir(exist_ok=True)
        
        # 취약점 패턴들
        self.vulnerability_patterns = {
            'xss_direct_output': {
                'pattern': r'echo\s+\$?(?:_GET|_POST|_REQUEST|_COOKIE)\[.*?\](?!\s*\);?\s*$)',
                'severity': 'HIGH',
                'description': 'Direct output of user input without sanitization',
                'recommendation': 'Use esc_html(), esc_attr(), or wp_kses() before output'
            },
            'xss_printf': {
                'pattern': r'printf?\s*\(\s*["\'].*?%s.*?["\']\s*,.*?(?:_GET|_POST|_REQUEST)',
                'severity': 'HIGH',
                'description': 'Printf with unsanitized user input',
                'recommendation': 'Sanitize input before using in printf functions'
            },
            'sql_injection': {
                'pattern': r'\$wpdb\s*->\s*(?:query|get_results|get_var|get_col|get_row)\s*\(\s*["\'].*?\$(?:_GET|_POST|_REQUEST)',
                'severity': 'CRITICAL',
                'description': 'Direct SQL query with user input',
                'recommendation': 'Use $wpdb->prepare() for parameterized queries'
            },
            'file_inclusion': {
                'pattern': r'(?:include|require)(?:_once)?\s*\(\s*\$?(?:_GET|_POST|_REQUEST)',
                'severity': 'CRITICAL',
                'description': 'File inclusion with user-controlled input',
                'recommendation': 'Validate and sanitize file paths, use whitelist approach'
            },
            'command_injection': {
                'pattern': r'(?:exec|system|shell_exec|passthru|proc_open)\s*\(\s*.*?\$(?:_GET|_POST|_REQUEST)',
                'severity': 'CRITICAL',
                'description': 'Command execution with user input',
                'recommendation': 'Avoid command execution, use built-in PHP functions instead'
            },
            'path_traversal': {
                'pattern': r'(?:file_get_contents|fopen|readfile|unlink)\s*\(\s*.*?\$(?:_GET|_POST|_REQUEST)',
                'severity': 'HIGH',
                'description': 'File operation with user-controlled path',
                'recommendation': 'Validate file paths, use basename(), check against whitelist'
            },
            'csrf_missing': {
                'pattern': r'(?:_GET|_POST|_REQUEST).*?(?:update|delete|create|modify).*?(?!wp_verify_nonce|check_admin_referer)',
                'severity': 'MEDIUM',
                'description': 'Potential CSRF vulnerability - missing nonce verification',
                'recommendation': 'Use wp_verify_nonce() or check_admin_referer()'
            },
            'unvalidated_redirect': {
                'pattern': r'wp_redirect\s*\(\s*\$(?:_GET|_POST|_REQUEST)',
                'severity': 'MEDIUM',
                'description': 'Unvalidated redirect with user input',
                'recommendation': 'Validate redirect URLs against whitelist'
            },
            'information_disclosure': {
                'pattern': r'(?:var_dump|print_r|var_export)\s*\(\s*\$(?:_GET|_POST|_REQUEST|_SESSION)',
                'severity': 'LOW',
                'description': 'Information disclosure through debug functions',
                'recommendation': 'Remove debug statements from production code'
            }
        }
        
        # 안전한 함수들 (False Positive 방지)
        self.safe_functions = {
            'esc_html', 'esc_attr', 'esc_url', 'esc_js', 'esc_textarea',
            'sanitize_text_field', 'sanitize_email', 'sanitize_url',
            'wp_kses', 'wp_kses_post', 'intval', 'absint', 'floatval'
        }
    
    def extract_plugins(self) -> None:
        """ZIP 파일들을 압축 해제"""
        downloads_dir = self.base_dir / "downloads"
        if not downloads_dir.exists():
            print(f"Downloads directory not found: {downloads_dir}")
            return
        
        for zip_file in downloads_dir.glob("*.zip"):
            try:
                with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                    zip_ref.extractall(downloads_dir)
                    print(f"[+] Extracted: {zip_file.name}")
                zip_file.unlink()  # 압축 파일 삭제
            except Exception as e:
                print(f"[-] Failed to extract {zip_file}: {e}")
    
    def get_plugin_metadata(self, plugin_name: str) -> Optional[PluginInfo]:
        """WordPress.org에서 플러그인 메타데이터 수집"""
        try:
            url = f"https://wordpress.org/plugins/{plugin_name}/"
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # 메타데이터 추출
            version = soup.select_one('.plugin-meta li:contains("Version") strong')
            updated = soup.select_one('.plugin-meta li:contains("Last updated") strong')
            installs = soup.select_one('.plugin-meta li:contains("Active installations") strong')
            tested = soup.select_one('.plugin-meta li:contains("Tested up to") strong')
            
            return PluginInfo(
                name=plugin_name,
                version=version.text.strip() if version else "Unknown",
                last_updated=updated.text.strip() if updated else "Unknown",
                active_installations=self._parse_installations(installs.text.strip() if installs else "0"),
                url=url,
                tested_wp_version=tested.text.strip() if tested else "Unknown"
            )
        except Exception as e:
            print(f"[-] Failed to get metadata for {plugin_name}: {e}")
            return None
    
    def _parse_installations(self, install_text: str) -> int:
        """설치 수 텍스트를 숫자로 변환"""
        numbers = re.findall(r'\d+', install_text.replace(',', ''))
        return int(''.join(numbers)) if numbers else 0
    
    def analyze_code_context(self, file_content: str, match_start: int, match_end: int) -> str:
        """코드 컨텍스트 분석"""
        lines = file_content.split('\n')
        match_line = file_content[:match_start].count('\n')
        
        # 주변 5줄 컨텍스트
        start_line = max(0, match_line - 2)
        end_line = min(len(lines), match_line + 3)
        
        context_lines = []
        for i in range(start_line, end_line):
            prefix = ">>> " if i == match_line else "    "
            context_lines.append(f"{prefix}{i+1}: {lines[i]}")
        
        return '\n'.join(context_lines)
    
    def calculate_confidence(self, match: str, file_content: str, pattern_info: dict) -> int:
        """취약점 신뢰도 계산"""
        confidence = 70  # 기본 신뢰도
        
        # 안전한 함수가 근처에 있는지 확인
        surrounding_code = file_content[max(0, match.start()-200):match.end()+200]
        for safe_func in self.safe_functions:
            if safe_func in surrounding_code:
                confidence -= 20
                break
        
        # 관리자 권한 체크가 있는지 확인
        admin_checks = ['current_user_can', 'is_admin', 'wp_verify_nonce', 'check_admin_referer']
        for check in admin_checks:
            if check in surrounding_code:
                confidence -= 15
                break
        
        # 조건문 내부인지 확인
        if re.search(r'if\s*\(.*?\$(?:_GET|_POST|_REQUEST)', surrounding_code):
            confidence += 10
        
        return max(10, min(100, confidence))
    
    def scan_file(self, file_path: Path) -> List[VulnerabilityReport]:
        """단일 파일 스캔"""
        if not file_path.suffix == '.php':
            return []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except:
            try:
                content = file_path.read_text(encoding='latin1')
            except:
                return []
        
        # 주석 제거 (개선된 버전)
        content_no_comments = self._remove_comments(content)
        
        vulnerabilities = []
        plugin_name = self._extract_plugin_name(file_path)
        
        for vuln_type, pattern_info in self.vulnerability_patterns.items():
            for match in re.finditer(pattern_info['pattern'], content_no_comments, re.IGNORECASE | re.MULTILINE):
                line_number = content[:match.start()].count('\n') + 1
                context = self.analyze_code_context(content, match.start(), match.end())
                confidence = self.calculate_confidence(match, content, pattern_info)
                
                # 신뢰도가 너무 낮으면 제외
                if confidence < 30:
                    continue
                
                vulnerability = VulnerabilityReport(
                    plugin_name=plugin_name,
                    file_path=str(file_path),
                    line_number=line_number,
                    vulnerability_type=vuln_type,
                    severity=pattern_info['severity'],
                    code_snippet=match.group(),
                    description=pattern_info['description'],
                    recommendation=pattern_info['recommendation'],
                    context=context,
                    confidence=confidence,
                    timestamp=datetime.now().isoformat()
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _remove_comments(self, content: str) -> str:
        """PHP 주석 제거 (개선된 버전)"""
        # 문자열 내부의 주석 기호를 보호하기 위한 개선된 정규식
        content = re.sub(r'//(?=(?:[^"\']*["\'][^"\']*["\'])*[^"\']*$).*$', '', content, flags=re.MULTILINE)
        content = re.sub(r'/\*(?=(?:[^"\']*["\'][^"\']*["\'])*[^"\']*$).*?\*/', '', content, flags=re.DOTALL)
        return content
    
    def _extract_plugin_name(self, file_path: Path) -> str:
        """파일 경로에서 플러그인명 추출"""
        parts = file_path.parts
        downloads_idx = -1
        
        for i, part in enumerate(parts):
            if part == "downloads":
                downloads_idx = i
                break
        
        if downloads_idx != -1 and downloads_idx + 1 < len(parts):
            return parts[downloads_idx + 1]
        
        return file_path.parent.name
    
    def scan_all_plugins(self) -> Dict[str, List[VulnerabilityReport]]:
        """모든 플러그인 스캔"""
        downloads_dir = self.base_dir / "downloads"
        all_vulnerabilities = {}
        
        if not downloads_dir.exists():
            print("Downloads directory not found!")
            return {}
        
        # 모든 PHP 파일 찾기
        php_files = list(downloads_dir.rglob("*.php"))
        total_files = len(php_files)
        
        print(f"[+] Scanning {total_files} PHP files...")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_file = {executor.submit(self.scan_file, file_path): file_path 
                            for file_path in php_files}
            
            completed = 0
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    vulnerabilities = future.result()
                    if vulnerabilities:
                        plugin_name = self._extract_plugin_name(file_path)
                        if plugin_name not in all_vulnerabilities:
                            all_vulnerabilities[plugin_name] = []
                        all_vulnerabilities[plugin_name].extend(vulnerabilities)
                    
                    completed += 1
                    if completed % 100 == 0:
                        print(f"[+] Processed {completed}/{total_files} files...")
                        
                except Exception as e:
                    print(f"[-] Error scanning {file_path}: {e}")
        
        return all_vulnerabilities
    
    def generate_report(self, vulnerabilities: Dict[str, List[VulnerabilityReport]]) -> str:
        """상세 보고서 생성"""
        report_file = self.results_dir / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        html_report_file = self.results_dir / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        # JSON 보고서
        report_data = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_plugins': len(vulnerabilities),
            'total_vulnerabilities': sum(len(vulns) for vulns in vulnerabilities.values()),
            'plugins': {}
        }
        
        # 플러그인 메타데이터 수집 및 보고서 작성
        for plugin_name, vulns in vulnerabilities.items():
            plugin_info = self.get_plugin_metadata(plugin_name)
            
            # 취약점 유형별 통계
            vuln_type_count = {}
            severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            
            for vuln in vulns:
                severity_count[vuln.severity] += 1
                vuln_type = vuln.vulnerability_type.replace('_', ' ').title()
                vuln_type_count[vuln_type] = vuln_type_count.get(vuln_type, 0) + 1
            
            report_data['plugins'][plugin_name] = {
                'metadata': asdict(plugin_info) if plugin_info else {},
                'vulnerability_count': len(vulns),
                'severity_breakdown': severity_count,
                'vulnerability_types': vuln_type_count,
                'vulnerabilities': [asdict(vuln) for vuln in vulns]
            }
        
        # JSON 파일 저장
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        # HTML 보고서 생성
        self._generate_html_report(report_data, html_report_file)
        
        print(f"\n[+] Reports generated:")
        print(f"    JSON: {report_file}")
        print(f"    HTML: {html_report_file}")
        
        return str(report_file)
    
    def _generate_html_report(self, report_data: dict, output_file: Path) -> None:
        """HTML 보고서 생성"""
        html_template = """<!DOCTYPE html>
<html>
<head>
    <title>WordPress Plugin Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; }}
        .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; }}
        .plugin {{ border: 1px solid #bdc3c7; margin: 20px 0; }}
        .plugin-header {{ background: #34495e; color: white; padding: 10px; }}
        .vulnerability {{ margin: 10px; padding: 10px; border-left: 4px solid; }}
        .critical {{ border-left-color: #e74c3c; background: #fadbd8; }}
        .high {{ border-left-color: #f39c12; background: #fdeaa7; }}
        .medium {{ border-left-color: #f1c40f; background: #fcf3cf; }}
        .low {{ border-left-color: #27ae60; background: #d5f4e6; }}
        .code {{ background: #2c3e50; color: #ecf0f1; padding: 10px; font-family: monospace; }}
        pre {{ white-space: pre-wrap; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>WordPress Plugin Security Report</h1>
        <p>Generated: {timestamp}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Plugins Scanned:</strong> {total_plugins}</p>
        <p><strong>Total Vulnerabilities Found:</strong> {total_vulnerabilities}</p>
    </div>
    
    {plugin_sections}
</body>
</html>"""
        
        plugin_sections = ""
        for plugin_name, plugin_data in report_data['plugins'].items():
            metadata = plugin_data.get('metadata', {})
            vulns = plugin_data['vulnerabilities']
            vuln_types = plugin_data.get('vulnerability_types', {})
            
            # 취약점 유형 요약 생성
            type_summary = ""
            if vuln_types:
                sorted_types = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:5]
                type_items = []
                for vtype, count in sorted_types:
                    type_items.append(f"{vtype}: {count}")
                type_summary = ", ".join(type_items)
            
            plugin_section = f"""
            <div class="plugin">
                <div class="plugin-header">
                    <h2>{plugin_name}</h2>
                    <p>Version: {metadata.get('version', 'Unknown')} | 
                       Installations: {metadata.get('active_installations', 'Unknown'):,} | 
                       Last Updated: {metadata.get('last_updated', 'Unknown')}</p>
                    <p><strong>Main vulnerability types:</strong> {type_summary}</p>
                </div>
            """
            
            for vuln in vulns:
                vuln_html = f"""
                <div class="vulnerability {vuln['severity'].lower()}">
                    <h3>{vuln['vulnerability_type'].replace('_', ' ').title()} ({vuln['severity']})</h3>
                    <p><strong>File:</strong> {vuln['file_path']}</p>
                    <p><strong>Line:</strong> {vuln['line_number']}</p>
                    <p><strong>Description:</strong> {vuln['description']}</p>
                    <p><strong>Recommendation:</strong> {vuln['recommendation']}</p>
                    <p><strong>Confidence:</strong> {vuln['confidence']}%</p>
                    <div class="code">
                        <strong>Code Context:</strong>
                        <pre>{vuln['context']}</pre>
                    </div>
                </div>
                """
                plugin_section += vuln_html
            
            plugin_section += "</div>"
            plugin_sections += plugin_section
        
        html_content = html_template.format(
            timestamp=report_data['scan_timestamp'],
            total_plugins=report_data['total_plugins'],
            total_vulnerabilities=report_data['total_vulnerabilities'],
            plugin_sections=plugin_sections
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def print_summary(self, vulnerabilities: Dict[str, List[VulnerabilityReport]]) -> None:
        """스캔 결과 요약 출력"""
        if not vulnerabilities:
            print("\n[+] No vulnerabilities found!")
            return
        
        total_vulns = sum(len(vulns) for vulns in vulnerabilities.values())
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        vuln_type_count = {}
        
        for vulns in vulnerabilities.values():
            for vuln in vulns:
                severity_count[vuln.severity] += 1
                vuln_type = vuln.vulnerability_type.replace('_', ' ').title()
                vuln_type_count[vuln_type] = vuln_type_count.get(vuln_type, 0) + 1
        
        print(f"\n{'='*60}")
        print(f"SECURITY SCAN RESULTS")
        print(f"{'='*60}")
        print(f"Plugins scanned: {len(vulnerabilities)}")
        print(f"Total vulnerabilities: {total_vulns}")
        
        print(f"\nSeverity breakdown:")
        print(f"  🔴 CRITICAL: {severity_count['CRITICAL']}")
        print(f"  🟠 HIGH:     {severity_count['HIGH']}")
        print(f"  🟡 MEDIUM:   {severity_count['MEDIUM']}")
        print(f"  🟢 LOW:      {severity_count['LOW']}")
        
        print(f"\nVulnerability types found:")
        sorted_types = sorted(vuln_type_count.items(), key=lambda x: x[1], reverse=True)
        for vuln_type, count in sorted_types:
            icon = self._get_vuln_icon(vuln_type.lower().replace(' ', '_'))
            print(f"  {icon} {vuln_type}: {count}")
        
        # 상위 5개 가장 취약한 플러그인
        print(f"\nTop 5 most vulnerable plugins:")
        sorted_plugins = sorted(vulnerabilities.items(), key=lambda x: len(x[1]), reverse=True)
        for i, (plugin_name, vulns) in enumerate(sorted_plugins[:5], 1):
            # 해당 플러그인의 취약점 유형별 통계
            plugin_types = {}
            for vuln in vulns:
                vuln_type = vuln.vulnerability_type.replace('_', ' ').title()
                plugin_types[vuln_type] = plugin_types.get(vuln_type, 0) + 1
            
            top_types = sorted(plugin_types.items(), key=lambda x: x[1], reverse=True)[:3]
            type_summary = ', '.join([f"{t}: {c}" for t, c in top_types])
            
            print(f"  {i}. {plugin_name}: {len(vulns)} vulnerabilities")
            print(f"     Main types: {type_summary}")
    
    def _get_vuln_icon(self, vuln_type: str) -> str:
        """취약점 유형별 아이콘 반환"""
        icons = {
            'xss_direct_output': '💉',
            'xss_printf': '💉', 
            'sql_injection': '🗃️',
            'file_inclusion': '📁',
            'command_injection': '⚡',
            'path_traversal': '📂',
            'csrf_missing': '🔐',
            'unvalidated_redirect': '↗️',
            'information_disclosure': '👁️'
        }
        return icons.get(vuln_type, '⚠️')

def main():
    """메인 실행 함수"""
    base_dir = r"C:\Tools\Wordpress-Plugin-Scanner"
    scanner = SecurityScanner(base_dir)
    
    print("Advanced WordPress Plugin Security Scanner")
    print("=" * 50)
    
    # 1. ZIP 파일 압축 해제
    print("[1/4] Extracting plugin archives...")
    scanner.extract_plugins()
    
    # 2. 플러그인 스캔
    print("[2/4] Scanning for vulnerabilities...")
    vulnerabilities = scanner.scan_all_plugins()
    
    # 3. 결과 요약 출력
    print("[3/4] Analyzing results...")
    scanner.print_summary(vulnerabilities)
    
    # 4. 상세 보고서 생성
    print("[4/4] Generating detailed report...")
    report_file = scanner.generate_report(vulnerabilities)
    
    print(f"\n[+] Scan completed! Check {report_file} for detailed results.")

if __name__ == "__main__":
    main()
