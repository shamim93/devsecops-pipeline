"""
Report parsers for different security tools
Normalizes tool outputs to unified vulnerability schema
"""

import json
from typing import Dict, List


class BanditParser:
    """Parse Bandit SAST reports"""

    BANDIT_TO_CWE = {
        'B104': '605',
        'B105': '259',
        'B106': '259',
        'B107': '259',
        'B108': '377',
        'B110': '390',
        'B201': '94',
        'B301': '502',
        'B302': '502',
        'B303': '327',
        'B304': '327',
        'B305': '327',
        'B306': '377',
        'B307': '78',
        'B308': '79',
        'B310': '601',
        'B311': '330',
        'B312': '605',
        'B313': '611',
        'B314': '611',
        'B315': '611',
        'B316': '611',
        'B317': '611',
        'B318': '611',
        'B319': '611',
        'B320': '611',
        'B321': '321',
        'B322': '78',
        'B323': '295',
        'B324': '327',
        'B325': '330',
        'B401': '319',
        'B402': '319',
        'B403': '502',
        'B404': '78',
        'B405': '611',
        'B406': '611',
        'B407': '611',
        'B408': '611',
        'B409': '611',
        'B410': '611',
        'B411': '319',
        'B412': '319',
        'B413': '327',
        'B501': '295',
        'B502': '295',
        'B503': '295',
        'B504': '295',
        'B505': '326',
        'B506': '20',
        'B507': '295',
        'B601': '78',
        'B602': '78',
        'B603': '78',
        'B604': '78',
        'B605': '78',
        'B606': '78',
        'B607': '78',
        'B608': '89',
        'B609': '78',
        'B610': '89',
        'B611': '89',
        'B701': '94',
        'B702': '79',
        'B703': '79',
    }

    @staticmethod
    def parse(report_data: Dict) -> List[Dict]:
        vulnerabilities = []
        results = report_data.get('results', [])

        for item in results:
            test_id = item.get('test_id', '')
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


class SafetyParser:
    """Parse Safety SCA reports"""

    @staticmethod
    def parse(report_data) -> List[Dict]:
        vulnerabilities = []

        if isinstance(report_data, str):
            try:
                report_data = json.loads(report_data)
            except json.JSONDecodeError:
                return SafetyParser._parse_text_output(report_data)

        if not isinstance(report_data, dict):
            return vulnerabilities

        if 'raw_output' in report_data:
            return SafetyParser._parse_text_output(
                report_data['raw_output']
            )

        if 'scan_results' in report_data:
            return SafetyParser._parse_new_format(report_data)

        if 'vulnerabilities' in report_data:
            return SafetyParser._parse_old_format(report_data)

        if isinstance(report_data, list):
            return SafetyParser._parse_array_format(report_data)

        return vulnerabilities

    @staticmethod
    def _parse_new_format(report_data: Dict) -> List[Dict]:
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
                    'vulnerability_id': item.get(
                        'vulnerability_id', ''
                    ),
                    'title': (
                        f"Vulnerable dependency: {dep.get('name', '')}"
                    ),
                    'description': item.get('advisory', ''),
                    'severity': item.get('severity', 'medium').lower(),
                    'confidence': 'high',
                    'file_path': 'requirements.txt',
                    'line_number': 0,
                    'code_snippet': (
                        f"{dep.get('name', '')}=="
                        f"{dep.get('version', '')}"
                    ),
                    'cwe_id': '',
                    'cvss_score': (
                        item.get('cvss_v3_severity', {})
                        .get('base_score', 0)
                    ),
                    'references': [item.get('more_info_url', '')],
                }
                vulnerabilities.append(vuln)

        return vulnerabilities

    @staticmethod
    def _parse_old_format(report_data: Dict) -> List[Dict]:
        vulnerabilities = []

        for item in report_data.get('vulnerabilities', []):
            vuln = {
                'tool_name': 'Safety',
                'scan_type': 'sca',
                'vulnerability_id': item.get('vulnerability_id', ''),
                'title': (
                    f"Vulnerable: {item.get('package_name', '')}"
                ),
                'description': item.get('advisory', ''),
                'severity': item.get('severity', 'medium').lower(),
                'confidence': 'high',
                'file_path': 'requirements.txt',
                'line_number': 0,
                'code_snippet': (
                    f"{item.get('package_name', '')}=="
                    f"{item.get('analyzed_version', '')}"
                ),
                'cwe_id': '',
                'cvss_score': float(item.get('cvss', 0) or 0),
                'references': [item.get('more_info_url', '')],
            }
            vulnerabilities.append(vuln)

        return vulnerabilities

    @staticmethod
    def _parse_array_format(report_data: List) -> List[Dict]:
        vulnerabilities = []

        for item in report_data:
            if not isinstance(item, dict):
                continue
            vuln = {
                'tool_name': 'Safety',
                'scan_type': 'sca',
                'vulnerability_id': item.get(
                    'vulnerability_id', item.get('id', '')
                ),
                'title': (
                    f"Vulnerable: "
                    f"{item.get('package_name', item.get('package', ''))}"
                ),
                'description': item.get(
                    'advisory', item.get('description', '')
                ),
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
        import re
        vulnerabilities = []

        if not text:
            return vulnerabilities

        vuln_pattern = r'Vulnerability found in (\w[\w\-]*) version ([\d\.]+)'
        id_pattern = r'Vulnerability ID: ([^\n]+)'
        cve_pattern = r'(CVE-\d{4}-\d+)'

        blocks = re.split(r'-{10,}', text)

        for block in blocks:
            package_match = re.search(vuln_pattern, block)
            if not package_match:
                continue

            package_name = package_match.group(1)
            package_version = package_match.group(2)

            id_match = re.search(id_pattern, block)
            vuln_id = id_match.group(1).strip() if id_match else ''

            cve_match = re.search(cve_pattern, block)
            cve = cve_match.group(1) if cve_match else ''

            vuln = {
                'tool_name': 'Safety',
                'scan_type': 'sca',
                'vulnerability_id': cve or vuln_id,
                'title': f"Vulnerable dependency: {package_name}",
                'description': block.strip(),
                'severity': 'medium',
                'confidence': 'high',
                'file_path': 'requirements.txt',
                'line_number': 0,
                'code_snippet': f"{package_name}=={package_version}",
                'cwe_id': '',
                'cvss_score': 0,
                'references': [],
            }
            vulnerabilities.append(vuln)

        return vulnerabilities


class TrivyParser:
    """Parse Trivy container scan reports"""

    @staticmethod
    def parse(report_data: Dict) -> List[Dict]:
        vulnerabilities = []
        results = report_data.get('Results', [])

        for result in results:
            target = result.get('Target', '')
            vulns = result.get('Vulnerabilities', [])

            if not vulns:
                continue

            for item in vulns:
                vuln = {
                    'tool_name': 'Trivy',
                    'scan_type': 'container',
                    'vulnerability_id': item.get(
                        'VulnerabilityID', ''
                    ),
                    'title': (
                        f"{item.get('PkgName', '')}: "
                        f"{item.get('Title', '')}"
                    ),
                    'description': item.get('Description', ''),
                    'severity': item.get(
                        'Severity', 'MEDIUM'
                    ).lower(),
                    'confidence': 'high',
                    'file_path': target,
                    'line_number': 0,
                    'code_snippet': (
                        f"{item.get('PkgName', '')} "
                        f"{item.get('InstalledVersion', '')}"
                    ),
                    'cwe_id': '',
                    'cvss_score': TrivyParser._extract_cvss(
                        item.get('CVSS', {})
                    ),
                    'references': item.get('References', []),
                }
                vulnerabilities.append(vuln)

        return vulnerabilities

    @staticmethod
    def _extract_cvss(cvss_data: Dict) -> float:
        if isinstance(cvss_data, dict):
            for key, value in cvss_data.items():
                if isinstance(value, dict) and 'V3Score' in value:
                    return value['V3Score']
        return 0.0


class ZAPParser:
    """Parse OWASP ZAP DAST reports"""

    PLUGIN_TO_CWE = {
        '40012': '79',
        '40014': '79',
        '40018': '89',
        '90022': '306',
        '10202': '352',
        '10055': '16',
        '10096': '200',
        '10021': '614',
        '10017': '16',
        '10038': '1021',
        '10098': '16',
        '10019': '16',
        '10020': '16',
        '10036': '16',
        '10037': '16',
    }

    @staticmethod
    def parse(report_data: Dict) -> List[Dict]:
        vulnerabilities = []

        site = report_data.get('site', [])
        if not site:
            return vulnerabilities

        alerts = site[0].get('alerts', [])

        for alert in alerts:
            plugin_id = str(alert.get('pluginid', ''))
            instances = alert.get('instances', [])

            cwe_id = ZAPParser.PLUGIN_TO_CWE.get(
                plugin_id,
                str(alert.get('cweid', ''))
            )

            for instance in instances:
                vuln = {
                    'tool_name': 'OWASP ZAP',
                    'scan_type': 'dast',
                    'vulnerability_id': plugin_id,
                    'title': alert.get('name', ''),
                    'description': alert.get('desc', ''),
                    'severity': ZAPParser._map_risk(
                        alert.get('riskcode', '1')
                    ),
                    'confidence': alert.get(
                        'confidence', 'Medium'
                    ).lower(),
                    'file_path': instance.get('uri', ''),
                    'line_number': 0,
                    'code_snippet': instance.get('evidence', ''),
                    'cwe_id': cwe_id,
                    'references': (
                        alert.get('reference', '').split('\n')
                        if alert.get('reference') else []
                    ),
                }
                vulnerabilities.append(vuln)

        return vulnerabilities

    @staticmethod
    def _map_risk(riskcode: str) -> str:
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
        vulnerabilities = []

        if 'vulnerabilities' in report_data:
            for item in report_data.get('vulnerabilities', []):
                vuln = {
                    'tool_name': 'TruffleHog',
                    'scan_type': 'secret',
                    'vulnerability_id': item.get(
                        'vulnerability_id', ''
                    ),
                    'title': item.get('title', ''),
                    'description': item.get('description', ''),
                    'severity': item.get('severity', 'high').lower(),
                    'confidence': item.get(
                        'confidence', 'high'
                    ).lower(),
                    'file_path': item.get('file_path', ''),
                    'line_number': item.get('line_number', 0),
                    'code_snippet': item.get('code_snippet', ''),
                    'cwe_id': item.get('cwe_id', '798'),
                    'cvss_score': None,
                    'references': item.get('references', []),
                }
                vulnerabilities.append(vuln)

        elif 'SourceMetadata' in report_data:
            vuln = {
                'tool_name': 'TruffleHog',
                'scan_type': 'secret',
                'vulnerability_id': report_data.get(
                    'DetectorName', ''
                ),
                'title': (
                    f"Secret: {report_data.get('DetectorName', '')}"
                ),
                'description': f"Raw: {report_data.get('Raw', '')}",
                'severity': 'critical',
                'confidence': 'high',
                'file_path': (
                    report_data.get('SourceMetadata', {})
                    .get('Data', {})
                    .get('Filesystem', {})
                    .get('file', '')
                ),
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
        parser_class = UnifiedParser.PARSERS.get(tool_name.lower())

        if not parser_class:
            raise ValueError(f"Unknown tool: {tool_name}")

        return parser_class.parse(report_data)