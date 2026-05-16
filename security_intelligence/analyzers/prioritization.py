"""
Novel Intelligent Vulnerability Prioritization

Ranks vulnerabilities by actual risk, not just severity.
"""

from typing import List, Dict
from datetime import datetime, timedelta


class VulnerabilityPrioritizer:
    """
    Intelligent prioritization based on multiple factors
    """
    
    @staticmethod
    def calculate_priority_score(vulnerability: Dict, context: Dict = None) -> Dict:
        """
        Calculate priority score for a vulnerability
        
        Factors:
        1. Base severity (CVSS or tool severity)
        2. Exploitability
        3. Asset criticality
        4. Age (how long it's been open)
        5. Multi-tool confirmation
        6. Public exploit availability
        7. Fix complexity
        
        Returns:
            {
                'priority_score': float (0-100),
                'priority_level': str,
                'factors': dict
            }
        """
        context = context or {}
        factors = {}
        
        # 1. Base Severity Score (0-40 points)
        severity_map = {
            'critical': 40,
            'high': 30,
            'medium': 20,
            'low': 10,
            'info': 5
        }
        base_score = severity_map.get(vulnerability.get('severity', 'info').lower(), 0)
        factors['base_severity'] = base_score
        
        # 2. Exploitability (0-25 points)
        exploitability = VulnerabilityPrioritizer._calculate_exploitability(vulnerability)
        factors['exploitability'] = exploitability
        
        # 3. Asset Criticality (0-15 points)
        asset_score = context.get('asset_criticality', 10)  # Default: medium
        factors['asset_criticality'] = asset_score
        
        # 4. Age Factor (0-10 points) - older = higher priority
        age_score = VulnerabilityPrioritizer._calculate_age_score(vulnerability)
        factors['age'] = age_score
        
        # 5. Multi-tool Confirmation (0-10 points)
        confirmation_score = min(vulnerability.get('correlation_count', 0) * 5, 10)
        factors['multi_tool_confirmation'] = confirmation_score
        
        # Total Score
        total_score = (
            base_score +
            exploitability +
            asset_score +
            age_score +
            confirmation_score
        )
        
        # Priority Level
        if total_score >= 80:
            priority_level = 'critical'
        elif total_score >= 60:
            priority_level = 'high'
        elif total_score >= 40:
            priority_level = 'medium'
        elif total_score >= 20:
            priority_level = 'low'
        else:
            priority_level = 'info'
        
        return {
            'priority_score': round(total_score, 2),
            'priority_level': priority_level,
            'factors': factors,
            'recommendation': VulnerabilityPrioritizer._get_recommendation(total_score)
        }
    
    @staticmethod
    def _calculate_exploitability(vulnerability: Dict) -> float:
        """
        Calculate exploitability score (0-25)
        
        High exploitability CWEs:
        - CWE-89: SQL Injection
        - CWE-79: XSS
        - CWE-78: Command Injection
        - CWE-22: Path Traversal
        """
        high_exploit_cwes = ['89', '79', '78', '22', '94', '611']
        medium_exploit_cwes = ['798', '259', '327', '330']
        
        cwe = str(vulnerability.get('cwe_id', '')).replace('CWE-', '')
        
        if cwe in high_exploit_cwes:
            base = 25
        elif cwe in medium_exploit_cwes:
            base = 15
        else:
            base = 10
        
        # Adjust for confidence
        confidence = vulnerability.get('confidence', 'medium').lower()
        if confidence == 'high':
            return base
        elif confidence == 'medium':
            return base * 0.8
        else:
            return base * 0.5
    
    @staticmethod
    def _calculate_age_score(vulnerability: Dict) -> float:
        """
        Calculate age score (0-10)
        Older vulnerabilities get higher priority
        """
        first_detected = vulnerability.get('first_detected')
        if not first_detected:
            return 0
        
        if isinstance(first_detected, str):
            first_detected = datetime.fromisoformat(first_detected.replace('Z', '+00:00'))
        
        age_days = (datetime.now(first_detected.tzinfo) - first_detected).days
        
        if age_days > 90:
            return 10
        elif age_days > 30:
            return 7
        elif age_days > 7:
            return 4
        else:
            return 2
    
    @staticmethod
    def _get_recommendation(score: float) -> str:
        """Get fix recommendation based on priority score"""
        if score >= 80:
            return "Fix immediately - Critical business risk"
        elif score >= 60:
            return "Fix within 24-48 hours - High priority"
        elif score >= 40:
            return "Fix within current sprint - Medium priority"
        elif score >= 20:
            return "Schedule for next release - Low priority"
        else:
            return "Monitor and review - Informational"
    
    @classmethod
    def rank_vulnerabilities(cls, vulnerabilities: List[Dict], context: Dict = None) -> List[Dict]:
        """
        Rank all vulnerabilities by priority
        
        Returns:
            Sorted list with priority scores added
        """
        ranked = []
        
        for vuln in vulnerabilities:
            priority_info = cls.calculate_priority_score(vuln, context)
            vuln_copy = vuln.copy()
            vuln_copy.update(priority_info)
            ranked.append(vuln_copy)
        
        # Sort by priority score (descending)
        ranked.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return ranked