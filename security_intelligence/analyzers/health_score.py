"""
Security Health Score Algorithm
Novel contribution for DevSecOps thesis
"""

import math
from typing import Dict, List, Tuple


class SecurityHealthScoreCalculator:
    """
    Novel algorithm for calculating overall security health
    across multiple security tool categories.
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
    def calculate_risk_score(vulnerability: dict) -> float:
        """
        Calculate individual vulnerability risk score (0-100)
        Uses additive scoring to prevent score inflation.

        Factors:
        - Base severity (0-60 points)
        - Confidence adjustment (-10 to +10 points)
        - Exploitability bonus (0-20 points)
        - Multi-tool confirmation bonus (0-10 points)
        """
        severity = vulnerability.get('severity', 'info').lower()
        confidence = vulnerability.get('confidence', 'medium').lower()
        cwe = str(vulnerability.get('cwe_id', '')).replace('CWE-', '')
        correlation_count = vulnerability.get('correlation_count', 0)

        # Base severity score (0-60 points)
        base_scores = {
            'critical': 60,
            'high': 45,
            'medium': 30,
            'low': 15,
            'info': 5,
        }
        base_score = base_scores.get(severity, 5)

        # Confidence adjustment (-10 to +10 points)
        confidence_adjustments = {
            'high': 10,
            'medium': 0,
            'low': -10,
        }
        confidence_adj = confidence_adjustments.get(confidence, 0)

        # Exploitability bonus (0-20 points)
        high_exploit_cwes = ['89', '79', '78', '94', '611', '22']
        medium_exploit_cwes = ['798', '259', '327', '330']

        if cwe in high_exploit_cwes:
            exploit_bonus = 20
        elif cwe in medium_exploit_cwes:
            exploit_bonus = 10
        else:
            exploit_bonus = 0

        # Multi-tool confirmation bonus (0-10 points)
        correlation_bonus = min(correlation_count * 5, 10)

        # Final additive score (capped at 100)
        risk_score = (
            base_score +
            confidence_adj +
            exploit_bonus +
            correlation_bonus
        )

        return round(min(max(risk_score, 0), 100), 2)

    @staticmethod
    def calculate_component_score(vulnerabilities: List[Dict]) -> float:
        """
        Calculate score for a single security component (0-100)
        100 = perfect (no vulnerabilities)
        0 = critical issues

        Uses logarithmic penalty to reflect diminishing marginal risk.
        """
        if not vulnerabilities:
            return 100.0

        total_penalty = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            penalty = SecurityHealthScoreCalculator.SEVERITY_POINTS.get(
                severity, 0
            )

            # Confidence multiplier
            confidence = vuln.get('confidence', 'medium').lower()
            if confidence == 'high':
                penalty *= 1.5
            elif confidence == 'low':
                penalty *= 0.5

            total_penalty += penalty

        # Logarithmic decay formula
        score = max(0, 100 - (10 * math.log10(total_penalty + 1)))
        return round(score, 2)

    @classmethod
    def calculate_overall_score(
        cls,
        component_scores: Dict[str, float]
    ) -> Tuple[float, str]:
        """
        Calculate weighted overall score and assign grade.

        Returns:
            (overall_score, grade)
        """
        overall = 0.0
        for component, weight in cls.WEIGHTS.items():
            score = component_scores.get(component, 0)
            overall += score * weight

        overall = round(overall, 2)

        # Grade assignment
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


def calculate_trend_analysis(historical_scores: List[Dict]) -> Dict:
    """
    Calculate security trend over time.

    Returns trend direction and change percentage.
    """
    if len(historical_scores) < 2:
        return {
            'improving': None,
            'trend': 'insufficient_data',
            'change_percentage': 0,
            'average_score': (
                historical_scores[0]['overall_score']
                if historical_scores else 0
            )
        }

    recent = historical_scores[-5:]
    scores = [s['overall_score'] for s in recent]

    avg = sum(scores) / len(scores)
    first_score = scores[0]
    last_score = scores[-1]

    change = (
        ((last_score - first_score) / first_score) * 100
        if first_score > 0 else 0
    )

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