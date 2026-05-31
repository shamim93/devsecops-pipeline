"""
Report parsers for different security tools
"""

import json
from typing import Dict, List
from datetime import datetime


class BanditParser:
    """Parse Bandit SAST reports"""

    # Map Bandit test IDs to CWE IDs
    BANDIT_TO_CWE = {
        'B608': '89',   # SQL Injection
        'B105': '259',  # Hardcoded password string
        'B106': '259',  # Hardcoded password function arg
        'B107': '259',  # Hardcoded password default
        'B104': '605',  # Binding to all interfaces
        'B101': '703',  # Assert used
        'B102': '78',   # OS exec used
        'B103': '732',  # File permissions
        'B108': '377',  # Temp file
        'B110': '390',  # Try except pass
        'B201': '94',   # Flask debug true
        'B301': '502',  # Pickle
        'B302': '502',  # Marshal
        'B303': '327',  # MD5
        'B304': '327',  # Ciphers
        'B305': '327',  # Cipher modes
        'B306': '377',  # mktemp
        'B307': '78',   # eval
        'B308': '79',   # mark_safe XSS
        'B310': '601',  # URL open
        'B311': '330',  # Random
        'B312': '605',  # Telnet
        'B313': '611',  # XML
        'B314': '611',  # XML
        'B315': '611',  # XML
        'B316': '611',  # XML
        'B317': '611',  # XML
        'B318': '611',  # XML
        'B319': '611',  # XML
        'B320': '611',  # XML
        'B321': '321',  # FTP
        'B322': '78',   # Input
        'B323': '295',  # Unverified context
        'B324': '327',  # Hashlib
        'B325': '330',  # Pseudo random
        'B401': '319',  # Telnet import
        'B402': '319',  # FTP import
        'B403': '502',  # Pickle import
        'B404': '78',   # Subprocess import
        'B405': '611',  # XML import
        'B406': '611',  # XML import
        'B407': '611',  # XML import
        'B408': '611',  # XML import
        'B409': '611',  # XML import
        'B410': '611',  # XML import
        'B411': '319',  # XMLRPC import
        'B412': '319',  # HTTPoxy import
        'B413': '327',  # PyCrypto
        'B501': '295',  # SSL bad version
        'B502': '295',  # SSL insecure
        'B503': '295',  # SSL bad defaults
        'B504': '295',  # SSL no version
        'B505': '326',  # Weak crypto key
        'B506': '20',   # YAML load
        'B507': '295',  # SSH no host key
        'B601': '78',   # Paramiko
        'B602': '78',   # Subprocess shell
        'B603': '78',   # Subprocess no shell
        'B604': '78',   # Any other shell
        'B605': '78',   # Start process shell
        'B606': '78',   # Start process no shell
        'B607': '78',   # Start process partial path
        'B608': '89',   # SQL injection
        'B609': '78',   # Wildcard injection
        'B610': '89',   # Django extra
        'B611': '89',   # Django rawsql
        'B701': '94',   # Jinja2 autoescape
        'B702': '79',   # Mako templates
        'B703': '79',   # Django mark safe
    }

    @staticmethod
    def parse(report_data: Dict) -> List[Dict]:
        """Parse Bandit JSON report"""
        vulnerabilities = []

        results = report_data.get('results', [])

        for item in results:
            test_id = item.get('test_id', '')

            # Get CWE from mapping or from report
            cwe_data = item.get('issue_cwe', {})
            if isinstance(cwe_data, dict):
                cwe_id = str(cwe_data.get('id', ''))
            else:
                cwe_id = str(cwe_data)

            # Fall back to mapping if no CWE in report
            if not cwe_id:
                cwe_id = BanditParser.BANDIT_TO_CWE.get(test_id, '')

            vuln = {
                'tool_name': 'Bandit',
                'scan_type': 'sast',
                'vulnerability_id': test_id,
                'title': item.get('issue_text', ''),
                'description': (
                    f"{item.get('issue_text', '')} - "
                    f"{item.get('more_info', '')}"
                ),
                'severity': item.get(
                    'issue_severity', 'MEDIUM'
                ).lower(),
                'confidence': item.get(
                    'issue_confidence', 'MEDIUM'
                ).lower(),
                'file_path': item.get('filename', ''),
                'line_number': item.get('line_number', 0),
                'code_snippet': item.get('code', ''),
                'cwe_id': cwe_id,
                'references': (
                    [item.get('more_info', '')]
                    if item.get('more_info') else []
                ),
            }
            vulnerabilities.append(vuln)

        return vulnerabilities
    """Parse Bandit SAST reports"""
    
    @staticmethod
    def parse(report_data: Dict) -> List[Dict]:
        """
        Parse Bandit JSON report
        
        Returns list of normalized vulnerabilities
        """
        vulnerabilities = []
        
        results = report_data.get('results', [])
        
        for item in results:
            vuln = {
                'tool_name': 'Bandit',
                'scan_type': 'sast',
                'vulnerability_id': item.get('test_id', ''),
                'title': item.get('issue_text', ''),
                'description': f"{item.get('issue_text', '')} - {item.get('more_info', '')}",
                'severity': item.get('issue_severity', 'MEDIUM').lower(),
                'confidence': item.get('issue_confidence', 'MEDIUM').lower(),
                'file_path': item.get('filename', ''),
                'line_number': item.get('line_number', 0),
                'code_snippet': item.get('code', ''),
                'cwe_id': item.get('issue_cwe', {}).get('id', '') if isinstance(item.get('issue_cwe'), dict) else '',
                'references': [item.get('more_info', '')] if item.get('more_info') else [],
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities


class SafetyParser:
    """Parse Safety SCA reports - handles multiple output formats"""
    
    @staticmethod
    def parse(report_data) -> List[Dict]:
        """
        Parse Safety JSON report
        Handles multiple Safety versions and formats
        """
        vulnerabilities = []
        
        # Handle string input
        if isinstance(report_data, str):
            try:
                report_data = json.loads(report_data)
            except json.JSONDecodeError:
                return SafetyParser._parse_text_output(report_data)
        
        if not isinstance(report_data, dict):
            return vulnerabilities
        
        # Handle raw text output wrapped in JSON
        if 'raw_output' in report_data:
            return SafetyParser._parse_text_output(report_data['raw_output'])
        
        # Format 1: New Safety scan format
        # {"scan_results": {"dependencies": [...]}}
        if 'scan_results' in report_data:
            return SafetyParser._parse_new_format(report_data)
        
        # Format 2: Old Safety check format
        # {"vulnerabilities": [...]}
        if 'vulnerabilities' in report_data:
            return SafetyParser._parse_old_format(report_data)
        
        # Format 3: Array format
        # [{"vulnerability_id": ...}]
        if isinstance(report_data, list):
            return SafetyParser._parse_array_format(report_data)
        
        return vulnerabilities
    
    @staticmethod
    def _parse_new_format(report_data: Dict) -> List[Dict]:
        """Parse new Safety scan format"""
        vulnerabilities = []
        
        scan_results = report_data.get('scan_results', {})
        dependencies = scan_results.get('dependencies', [])
        
        for dep in dependencies:
            dep_vulns = dep.get('vulnerabilities', {})
            found = dep_vulns.get('found', [])
            
            for item in found:
                vuln = {
                    'tool_name': 'Safety',
                    'scan_type': 'sca',
                    'vulnerability_id': item.get('vulnerability_id', ''),
                    'title': f"Vulnerable dependency: {dep.get('name', '')}",
                    'description': item.get('advisory', ''),
                    'severity': item.get('severity', 'medium').lower(),
                    'confidence': 'high',
                    'file_path': 'requirements.txt',
                    'line_number': 0,
                    'code_snippet': f"{dep.get('name', '')}=={dep.get('version', '')}",
                    'cwe_id': '',
                    'cvss_score': item.get('cvss_v3_severity', {}).get('base_score', 0),
                    'references': [item.get('more_info_url', '')],
                }
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    @staticmethod
    def _parse_old_format(report_data: Dict) -> List[Dict]:
        """Parse old Safety check format"""
        vulnerabilities = []
        
        for item in report_data.get('vulnerabilities', []):
            vuln = {
                'tool_name': 'Safety',
                'scan_type': 'sca',
                'vulnerability_id': item.get('vulnerability_id', ''),
                'title': f"Vulnerable: {item.get('package_name', '')}",
                'description': item.get('advisory', ''),
                'severity': item.get('severity', 'medium').lower(),
                'confidence': 'high',
                'file_path': 'requirements.txt',
                'line_number': 0,
                'code_snippet': f"{item.get('package_name', '')}=={item.get('analyzed_version', '')}",
                'cwe_id': '',
                'cvss_score': float(item.get('cvss', 0) or 0),
                'references': [item.get('more_info_url', '')],
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    @staticmethod
    def _parse_array_format(report_data: List) -> List[Dict]:
        """Parse array format"""
        vulnerabilities = []
        
        for item in report_data:
            if not isinstance(item, dict):
                continue
            vuln = {
                'tool_name': 'Safety',
                'scan_type': 'sca',
                'vulnerability_id': item.get('vulnerability_id', item.get('id', '')),
                'title': f"Vulnerable: {item.get('package_name', item.get('package', ''))}",
                'description': item.get('advisory', item.get('description', '')),
                'severity': item.get('severity', 'medium').lower(),
                'confidence': 'high',
                'file_path': 'requirements.txt',
                'line_number': 0,
                'code_snippet': '',
                'cwe_id': '',
                'cvss_score': 0,
                'references': [],
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    @staticmethod
    def _parse_text_output(text: str) -> List[Dict]:
        """
        Parse Safety text output when JSON is not available
        Extracts vulnerability info from formatted text
        """
        vulnerabilities = []
        
        if not text:
            return vulnerabilities
        
        import re
        
        # Pattern: "Vulnerability found in PACKAGE version VERSION"
        vuln_pattern = r'Vulnerability found in (\w[\w\-]*) version ([\d\.]+)'
        advisory_pattern = r'ADVISORY: (.+?)(?=CVE|For more|$)'
        cve_pattern = r'(CVE-\d{4}-\d+)'
        id_pattern = r'Vulnerability ID: ([^\n]+)'
        
        # Split by vulnerability blocks
        blocks = re.split(r'-{10,}', text)
        
        for block in blocks:
            package_match = re.search(vuln_pattern, block)
            if not package_match:
                continue
            
            package_name = package_match.group(1)
            package_version = package_match.group(2)
            
            # Extract vulnerability ID
            id_match = re.search(id_pattern, block)
            vuln_id = id_match.group(1).strip() if id_match else ''
            
            # Extract advisory
            advisory_match = re.search(advisory_pattern, block, re.DOTALL)
            advisory = advisory_match.group(1).strip() if advisory_match else ''
            
            # Extract CVE
            cve_match = re.search(cve_pattern, block)
            cve = cve_match.group(1) if cve_match else ''
            
            vuln = {
                'tool_name': 'Safety',
                'scan_type': 'sca',
                'vulnerability_id': cve or vuln_id,
                'title': f"Vulnerable dependency: {package_name}",
                'description': advisory,
                'severity': 'medium',
                'confidence': 'high',
                'file_path': 'requirements.txt',
                'line_number': 0,
                'code_snippet': f"{package_name}=={package_version}",
                'cwe_id': '',
                'cvss_score': 0,
                'references': [f"https://pyup.io/{vuln_id}"] if vuln_id else [],
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    @staticmethod
    def _map_severity(severity: str) -> str:
        """Map Safety severity to standard"""
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
        }
        return severity_map.get(severity.lower(), 'medium')


class TrivyParser:
    """Parse Trivy container scan reports"""
    
    @staticmethod
    def parse(report_data: Dict) -> List[Dict]:
        """Parse Trivy JSON report"""
        vulnerabilities = []
        
        results = report_data.get('Results', [])
        
        for result in results:
            target = result.get('Target', '')
            vulns = result.get('Vulnerabilities', [])
            
            for item in vulns:
                vuln = {
                    'tool_name': 'Trivy',
                    'scan_type': 'container',
                    'vulnerability_id': item.get('VulnerabilityID', ''),
                    'title': f"{item.get('PkgName', '')}: {item.get('Title', '')}",
                    'description': item.get('Description', ''),
                    'severity': item.get('Severity', 'MEDIUM').lower(),
                    'confidence': 'high',
                    'file_path': target,
                    'line_number': 0,
                    'code_snippet': f"{item.get('PkgName', '')} {item.get('InstalledVersion', '')}",
                    'cwe_id': '',
                    'cvss_score': TrivyParser._extract_cvss(item.get('CVSS', {})),
                    'references': item.get('References', []),
                }
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    @staticmethod
    def _extract_cvss(cvss_data: Dict) -> float:
        """Extract CVSS score from Trivy format"""
        if isinstance(cvss_data, dict):
            for key, value in cvss_data.items():
                if isinstance(value, dict) and 'V3Score' in value:
                    return value['V3Score']
        return 0.0


class ZAPParser:
    """Parse OWASP ZAP DAST reports"""
    
    @staticmethod
    def parse(report_data: Dict) -> List[Dict]:
        """Parse ZAP JSON report"""
        vulnerabilities = []
        
        site = report_data.get('site', [])
        if not site:
            return vulnerabilities
        
        alerts = site[0].get('alerts', [])
        
        for alert in alerts:
            instances = alert.get('instances', [])
            
            for instance in instances:
                vuln = {
                    'tool_name': 'OWASP ZAP',
                    'scan_type': 'dast',
                    'vulnerability_id': str(alert.get('pluginid', '')),
                    'title': alert.get('name', ''),
                    'description': alert.get('desc', ''),
                    'severity': ZAPParser._map_risk(alert.get('riskcode', '1')),
                    'confidence': alert.get('confidence', 'Medium').lower(),
                    'file_path': instance.get('uri', ''),
                    'line_number': 0,
                    'code_snippet': instance.get('evidence', ''),
                    'cwe_id': str(alert.get('cweid', '')),
                    'references': alert.get('reference', '').split('\n') if alert.get('reference') else [],
                }
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    @staticmethod
    def _map_risk(riskcode: str) -> str:
        """Map ZAP risk code to severity"""
        risk_map = {
            '3': 'high',
            '2': 'medium',
            '1': 'low',
            '0': 'info',
        }
        return risk_map.get(str(riskcode), 'medium')

class TruffleHogParser:
    """Parse TruffleHog secret scanning reports"""
    
    @staticmethod
    def parse(report_data: Dict) -> List[Dict]:
        """
        Parse TruffleHog report
        Handles both our custom format and native TruffleHog format
        """
        vulnerabilities = []
        
        # Handle our custom format
        if 'vulnerabilities' in report_data:
            for item in report_data.get('vulnerabilities', []):
                vuln = {
                    'tool_name': 'TruffleHog',
                    'scan_type': 'secret',
                    'vulnerability_id': item.get('vulnerability_id', ''),
                    'title': item.get('title', ''),
                    'description': item.get('description', ''),
                    'severity': item.get('severity', 'high').lower(),
                    'confidence': item.get('confidence', 'high').lower(),
                    'file_path': item.get('file_path', ''),
                    'line_number': item.get('line_number', 0),
                    'code_snippet': item.get('code_snippet', ''),
                    'cwe_id': item.get('cwe_id', '798'),
                    'cvss_score': None,
                    'references': item.get('references', []),
                }
                vulnerabilities.append(vuln)
        
        # Handle native TruffleHog format
        elif 'SourceMetadata' in report_data:
            vuln = {
                'tool_name': 'TruffleHog',
                'scan_type': 'secret',
                'vulnerability_id': report_data.get('DetectorName', ''),
                'title': f"Secret detected: {report_data.get('DetectorName', '')}",
                'description': f"Raw: {report_data.get('Raw', '')}",
                'severity': 'critical',
                'confidence': 'high',
                'file_path': report_data.get(
                    'SourceMetadata', {}
                ).get('Data', {}).get('Filesystem', {}).get('file', ''),
                'line_number': 0,
                'code_snippet': report_data.get('Raw', ''),
                'cwe_id': '798',
                'cvss_score': None,
                'references': [],
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
class UnifiedParser:
    """Unified parser for all security tools"""
    
    PARSERS = {
        'bandit': BanditParser,
        'safety': SafetyParser,
        'trivy': TrivyParser,
        'zap': ZAPParser,
        'trufflehog': TruffleHogParser, 
    }
    
    @staticmethod
    def parse_report(tool_name: str, report_data: Dict) -> List[Dict]:
        """
        Parse any security tool report
        
        Args:
            tool_name: 'bandit', 'safety', 'trivy', or 'zap'
            report_data: JSON report data
        
        Returns:
            List of normalized vulnerability dicts
        """
        parser_class = UnifiedParser.PARSERS.get(tool_name.lower())
        
        if not parser_class:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        return parser_class.parse(report_data)
    
