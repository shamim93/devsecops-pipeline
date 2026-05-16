"""
Security Health Score Algorithm

Calculates a weighted security score based on multiple security tool findings.
"""
from typing import Dict, List, Tuple
import math

class SecurityHealthScoreCalculator:
    """
    algorithm for calculating overall security health
    Weights based on risk impact research:
    - Code Security (SAST): 30% - Direct code vulnerabilities
    - Dependency Health (SCA): 25% - Known CVEs in dependencies  
    - Runtime Security (DAST): 20% - Runtime vulnerabilities
    - Secret Exposure: 15% - Exposed credentials
    - Container Security: 10% - Image vulnerabilities
    """
    WEIGHTS = {
        'code_security': 0.30,
        'dependency_health': 0.25,
        'runtime_security': 0.20,
        'secret_exposure': 0.15,
        'container_security': 0.10,
    }
    
    SEVERITY_POINTS = {
        'critical': 100,
        'high': 75,
        'medium': 40,
        'low': 15,
        'info': 5,
    }
    
    @staticmethod
    def calculate_component_score(vulnerabilities: List[Dict]) -> float:
        """
        Calculate score for a single component (0-100)
        100 = perfect (no vulnerabilities)
        0 = critical issues
        """
        if not vulnerabilities:
            return 100.0
        
        total_penalty = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            penalty = SecurityHealthScoreCalculator.SEVERITY_POINTS.get(severity, 0)
            
            # Increase penalty for high confidence
            confidence = vuln.get('confidence', 'medium').lower()
            if confidence == 'high':
                penalty *= 1.5
            elif confidence == 'low':
                penalty *= 0.5
            
            total_penalty += penalty
        
        # Logarithmic decay - many small issues < few critical issues
        score = max(0, 100 - (10 * math.log10(total_penalty + 1)))
        return round(score, 2)
    
    @classmethod
    def calculate_overall_score(cls, component_scores: Dict[str, float]) -> Tuple[float, str]:
        """
        Calculate weighted overall score and assign grade
        Returns:
            (overall_score, grade)
        """
        overall = 0.0
        for component, weight in cls.WEIGHTS.items():
            score = component_scores.get(component, 0)
            overall += score * weight
        
        overall = round(overall, 2)
        
        # Assign grade
        if overall >= 90:
            grade = 'A'
        elif overall >= 80:
            grade = 'B'
        elif overall >= 70:
            grade = 'C'
        elif overall >= 60:
            grade = 'D'
        else:
            grade = 'F'
        
        return overall, grade
    
    @staticmethod
    def calculate_risk_score(vulnerability: Dict) -> float:
        """
        Novel: Calculate individual vulnerability risk score
        
        Factors:
        - Base severity
        - Exploitability
        - Confidence level
        - Whether it's confirmed by multiple tools
        """
        severity = vulnerability.get('severity', 'info').lower()
        base_score = SecurityHealthScoreCalculator.SEVERITY_POINTS.get(severity, 0)
        
        # Confidence multiplier
        confidence = vulnerability.get('confidence', 'medium').lower()
        confidence_multiplier = {
            'high': 1.5,
            'medium': 1.0,
            'low': 0.6,
        }.get(confidence, 1.0)
        
        # Exploitability (based on CWE if available)
        exploitable_cwes = ['89', '79', '78', '94', '611']  # SQL, XSS, Command Injection, etc.
        cwe = vulnerability.get('cwe_id', '').replace('CWE-', '')
        exploitability_multiplier = 1.5 if cwe in exploitable_cwes else 1.0
        
        # Correlation multiplier (if detected by multiple tools)
        correlation_count = vulnerability.get('correlation_count', 0)
        correlation_multiplier = 1 + (0.2 * correlation_count)
        
        risk_score = (
            base_score * 
            confidence_multiplier * 
            exploitability_multiplier * 
            correlation_multiplier
        )
        
        return round(min(risk_score, 100), 2)


def calculate_trend_analysis(historical_scores: List[Dict]) -> Dict:
    """
    Calculate security trends over time
    
    Returns:
        {
            'improving': bool,
            'trend': 'up' | 'down' | 'stable',
            'change_percentage': float,
            'average_score': float
        }
    """
    if len(historical_scores) < 2:
        return {
            'improving': None,
            'trend': 'insufficient_data',
            'change_percentage': 0,
            'average_score': historical_scores[0]['overall_score'] if historical_scores else 0
        }
    
    recent = historical_scores[-5:]  # Last 5 scans
    scores = [s['overall_score'] for s in recent]
    
    avg = sum(scores) / len(scores)
    first_score = scores[0]
    last_score = scores[-1]
    
    change = ((last_score - first_score) / first_score) * 100 if first_score > 0 else 0
    
    if change > 5:
        trend = 'up'
        improving = True
    elif change < -5:
        trend = 'down'
        improving = False
    else:
        trend = 'stable'
        improving = None
    
    return {
        'improving': improving,
        'trend': trend,
        'change_percentage': round(change, 2),
        'average_score': round(avg, 2)
    }