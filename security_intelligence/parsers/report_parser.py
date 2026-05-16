"""
Report parsers for different security tools
"""

import json
from typing import Dict, List
from datetime import datetime


class BanditParser:
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
    """Parse Safety SCA reports"""
    
    @staticmethod
    def parse(report_data: Dict) -> List[Dict]:
        """Parse Safety JSON report"""
        vulnerabilities = []
        
        vulns = report_data.get('vulnerabilities', [])
        
        for item in vulns:
            vuln = {
                'tool_name': 'Safety',
                'scan_type': 'sca',
                'vulnerability_id': item.get('vulnerability_id', ''),
                'title': f"Vulnerable dependency: {item.get('package_name', '')}",
                'description': item.get('advisory', ''),
                'severity': SafetyParser._map_severity(item.get('severity', 'medium')),
                'confidence': 'high',  # Safety findings are typically high confidence
                'file_path': 'requirements.txt',
                'line_number': 0,
                'code_snippet': f"{item.get('package_name', '')}=={item.get('analyzed_version', '')}",
                'cwe_id': '',
                'cvss_score': item.get('cvss', 0),
                'references': [item.get('more_info_url', '')] if item.get('more_info_url') else [],
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


class UnifiedParser:
    """Unified parser for all security tools"""
    
    PARSERS = {
        'bandit': BanditParser,
        'safety': SafetyParser,
        'trivy': TrivyParser,
        'zap': ZAPParser,
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