"""
Management command to import security scan reports
"""

from django.core.management.base import BaseCommand
import json
import os
from security_intelligence.models import SecurityScan, Vulnerability, SecurityHealthScore
from security_intelligence.parsers.report_parser import UnifiedParser
from security_intelligence.analyzers.health_score import SecurityHealthScoreCalculator
from security_intelligence.correlators.vulnerability_correlator import VulnerabilityCorrelator
from security_intelligence.analyzers.prioritization import VulnerabilityPrioritizer

class Command(BaseCommand):
    help = 'Import security scan reports and calculate scores'
    
    def add_arguments(self, parser):
        parser.add_argument('--scan-dir', type=str, help='Directory containing scan reports')
        parser.add_argument('--commit-sha', type=str, default='', help='Git commit SHA')
    
    def handle(self, *args, **options):
        scan_dir = options.get('scan_dir', 'scan_reports')
        commit_sha = options.get('commit_sha', '')
        
        self.stdout.write(f"Importing scans from: {scan_dir}")
        
        # Parse each report
        vulnerabilities_by_tool = {}
        
        tools_config = [
            ('bandit', 'bandit-report.json', 'sast'),
            ('safety', 'safety-report.json', 'sca'),
            ('trivy', 'trivy-report.json', 'container'),
            ('zap', 'zap-full-report.json', 'dast'),
            ('trufflehog', 'trufflehog-report.json', 'secret'),
        ]
        
        for tool_name, filename, scan_type in tools_config:
            filepath = os.path.join(scan_dir, filename)
            
            if not os.path.exists(filepath):
                self.stdout.write(self.style.WARNING(f"Skipping {tool_name}: {filepath} not found"))
                continue
            
            try:
                # Try to read as JSON first
                with open(filepath, 'r') as f:
                    content = f.read().strip()
                if not content:
                    self.stdout.write(self.style.WARNING(f"Empty report for {tool_name}, skipping"))
                    continue
                try:
                    report_data = json.loads(content)
                except json.JSONDecodeError:
                    # Not valid JSON, treat as text
                    self.stdout.write(self.style.WARNING(f"{tool_name} report is not JSON, parsing as text"))
                    report_data = {'raw_output': content}

                # Create scan record
                scan = SecurityScan.objects.create(
                        scan_type=scan_type,
                        tool_name=tool_name,
                        commit_sha=commit_sha,
                        raw_report=report_data if isinstance(report_data, dict) else {}
                    )
                            
                # Parse vulnerabilities
                vulns = UnifiedParser.parse_report(tool_name, report_data)
                vulnerabilities_by_tool[tool_name] = vulns
                        
                # Save to database
                for vuln_data in vulns:
                    try:
                        priority_info = VulnerabilityPrioritizer.calculate_priority_score({
                            'severity': vuln_data.get('severity', 'medium'),
                            'confidence': vuln_data.get('confidence', 'medium'),
                            'cwe_id': str(vuln_data.get('cwe_id', '')),
                            'first_detected': None,
                            'correlation_count': 0,
                        })
                        risk_score = priority_info['priority_score']
                        
                        Vulnerability.objects.create(
                            scan=scan,
                            vulnerability_id=vuln_data.get('vulnerability_id', ''),
                            title=vuln_data.get('title', '')[:255],
                            description=vuln_data.get('description', ''),
                            severity=vuln_data.get('severity', 'medium'),
                            confidence=vuln_data.get('confidence', 'medium'),
                            file_path=vuln_data.get('file_path', '')[:500],
                            line_number=vuln_data.get('line_number') or 0,
                            code_snippet=vuln_data.get('code_snippet', ''),
                            cwe_id=str(vuln_data.get('cwe_id', ''))[:20],
                            cvss_score=vuln_data.get('cvss_score'),
                            references=vuln_data.get('references', []),
                            calculated_risk_score=risk_score,
                        )
                        
                    except Exception as e:
                        self.stdout.write(self.style.WARNING(f"Error saving vulnerability: {e}"))
                        continue
                self.stdout.write(self.style.SUCCESS(
                f" Imported {len(vulns)} vulnerabilities from {tool_name}"
            ))
                    
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error importing {tool_name}: {e}"))
        
        # Calculate correlations
        self.stdout.write("\nCalculating cross-tool correlations...")
        all_vulns = []
        for vulns in vulnerabilities_by_tool.values():
            all_vulns.extend(vulns)
        
        correlations = VulnerabilityCorrelator.find_correlations(all_vulns)
        self.stdout.write(self.style.SUCCESS(f"Found {len(correlations)} correlated vulnerability groups"))
        
        # Calculate Security Health Score
        self.stdout.write("\nCalculating Security Health Score...")
        
        component_scores = {
            'code_security': SecurityHealthScoreCalculator.calculate_component_score(
                vulnerabilities_by_tool.get('bandit', [])
            ),
            'dependency_health': SecurityHealthScoreCalculator.calculate_component_score(
                vulnerabilities_by_tool.get('safety', [])
            ),
            'runtime_security': SecurityHealthScoreCalculator.calculate_component_score(
                vulnerabilities_by_tool.get('zap', [])
            ),
            'secret_exposure': 50.0,  # Placeholder - TruffleHog results need parsing
            'container_security': SecurityHealthScoreCalculator.calculate_component_score(
                vulnerabilities_by_tool.get('trivy', [])
            ),
        }
        
        overall_score, grade = SecurityHealthScoreCalculator.calculate_overall_score(component_scores)
        
        # Count by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vulns in vulnerabilities_by_tool.values():
            for v in vulns:
                severity = v.get('severity', 'info')
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        # Save health score
        health_score = SecurityHealthScore.objects.create(
            commit_sha=commit_sha,
            code_security_score=component_scores['code_security'],
            dependency_health_score=component_scores['dependency_health'],
            runtime_security_score=component_scores['runtime_security'],
            secret_exposure_score=component_scores['secret_exposure'],
            container_security_score=component_scores['container_security'],
            overall_score=overall_score,
            grade=grade,
            total_vulnerabilities=len(all_vulns),
            critical_count=severity_counts['critical'],
            high_count=severity_counts['high'],
            medium_count=severity_counts['medium'],
            low_count=severity_counts['low'],
        )
        # Step 3: Run correlation engine
        self.stdout.write("\nRunning correlation engine...")

        # Get all vulnerabilities as dicts
        all_vuln_dicts = list(Vulnerability.objects.filter(
            scan__in=SecurityScan.objects.filter(
                commit_sha=commit_sha
            )
        ).values(
            'id', 'title', 'severity', 'confidence',
            'file_path', 'line_number', 'cwe_id',
            'description', 'scan__tool_name'
        ))
        # tool name
        for v in all_vuln_dicts:
            v['tool_name'] = v.pop('scan__tool_name')

        # Find correlations
        correlations = VulnerabilityCorrelator.find_correlations(all_vuln_dicts)

        # Build correlation count map
        correlation_counts = {}
        for group in correlations:
            primary_id = group['primary']['id']
            count = len(group['correlated'])
            correlation_counts[primary_id] = count
            for corr in group['correlated']:
                corr_id = corr['vulnerability']['id']
                correlation_counts[corr_id] = count

        self.stdout.write(
            self.style.SUCCESS(
                f"Found {len(correlations)} correlation groups"
            )
        )

        # Step 4: Update risk scores with correlation counts
        self.stdout.write("\nUpdating risk scores with correlation data...")
        for vuln in Vulnerability.objects.filter(
            scan__commit_sha=commit_sha
        ):
            corr_count = correlation_counts.get(vuln.id, 0)
            priority_info = VulnerabilityPrioritizer.calculate_priority_score({
                'severity': vuln.severity,
                'confidence': vuln.confidence,
                'cwe_id': vuln.cwe_id,
                'first_detected': vuln.first_detected,
                'correlation_count': corr_count,
            })
            vuln.calculated_risk_score = priority_info['priority_score']
            vuln.save()
        
        self.stdout.write(self.style.SUCCESS(f"\n{'='*60}"))
        self.stdout.write(self.style.SUCCESS(f"Security Health Score: {overall_score:.1f} ({grade})"))
        self.stdout.write(self.style.SUCCESS(f"{'='*60}"))
        self.stdout.write(f"Code Security: {component_scores['code_security']:.1f}")
        self.stdout.write(f"Dependency Health: {component_scores['dependency_health']:.1f}")
        self.stdout.write(f"Runtime Security: {component_scores['runtime_security']:.1f}")
        self.stdout.write(f"Container Security: {component_scores['container_security']:.1f}")
        self.stdout.write(self.style.SUCCESS(f"{'='*60}\n"))