from django.db import models
from django.utils import timezone
import json

class SecurityScan(models.Model):
    """Represents a security scan execution"""
    SCAN_TYPES = [
        ('sast', 'SAST (Static Analysis)'),
        ('sca', 'SCA (Dependency Analysis)'),
        ('dast', 'DAST (Dynamic Analysis)'),
        ('secret', 'Secret Scanning'),
        ('container', 'Container Scanning'),
    ]
    
    scan_type = models.CharField(max_length=20, choices=SCAN_TYPES)
    tool_name = models.CharField(max_length=50)  # bandit, safety, zap, etc.
    scan_date = models.DateTimeField(default=timezone.now)
    commit_sha = models.CharField(max_length=40, blank=True)
    branch = models.CharField(max_length=100, default='main')
    duration_seconds = models.IntegerField(default=0)
    raw_report = models.JSONField(default=dict)
    
    class Meta:
        ordering = ['-scan_date']
    
    def __str__(self):
        return f"{self.tool_name} - {self.scan_date.strftime('%Y-%m-%d %H:%M')}"


class Vulnerability(models.Model):
    """Represents a detected vulnerability"""
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]
    
    STATUS_CHOICES = [
        ('open', 'Open'),
        ('confirmed', 'Confirmed'),
        ('false_positive', 'False Positive'),
        ('fixed', 'Fixed'),
        ('accepted_risk', 'Accepted Risk'),
    ]
    
    scan = models.ForeignKey(SecurityScan, on_delete=models.CASCADE, related_name='vulnerabilities')
    vulnerability_id = models.CharField(max_length=100)  # CVE, CWE, or tool-specific ID
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    confidence = models.CharField(max_length=20, default='medium')
    
    # Location information
    file_path = models.CharField(max_length=500, blank=True)
    line_number = models.IntegerField(null=True, blank=True)
    code_snippet = models.TextField(blank=True)
    
    # Metadata
    cwe_id = models.CharField(max_length=20, blank=True)
    cvss_score = models.FloatField(null=True, blank=True)
    references = models.JSONField(default=list)
    
    # Status tracking
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='open')
    first_detected = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    
    # Novel: Risk score calculated by our algorithm
    calculated_risk_score = models.FloatField(default=0.0)
    
    class Meta:
        ordering = ['-calculated_risk_score', '-severity']
    
    def __str__(self):
        return f"{self.severity.upper()}: {self.title}"


class VulnerabilityCorrelation(models.Model):
    """Novel: Correlates same vulnerability detected by multiple tools"""
    
    primary_vulnerability = models.ForeignKey(
        Vulnerability, 
        on_delete=models.CASCADE, 
        related_name='correlations_as_primary'
    )
    correlated_vulnerabilities = models.ManyToManyField(
        Vulnerability, 
        related_name='correlations_as_correlated'
    )
    
    confidence_score = models.FloatField(default=0.0)  # 0-1 how sure we are they're the same
    correlation_method = models.CharField(max_length=50)  # file_match, cwe_match, description_similarity
    created_at = models.DateTimeField(default=timezone.now)
    
    def __str__(self):
        return f"Correlation: {self.primary_vulnerability.title}"


class SecurityHealthScore(models.Model):
    """Novel: Overall security health metrics"""
    
    calculated_at = models.DateTimeField(default=timezone.now)
    commit_sha = models.CharField(max_length=40, blank=True)
    
    # Individual scores (0-100)
    code_security_score = models.FloatField(default=0.0)
    dependency_health_score = models.FloatField(default=0.0)
    runtime_security_score = models.FloatField(default=0.0)
    secret_exposure_score = models.FloatField(default=0.0)
    container_security_score = models.FloatField(default=0.0)
    
    # Overall weighted score
    overall_score = models.FloatField(default=0.0)
    grade = models.CharField(max_length=2, default='F')  # A, B, C, D, F
    
    # Metrics
    total_vulnerabilities = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    
    class Meta:
        ordering = ['-calculated_at']
    
    def __str__(self):
        return f"Security Score: {self.overall_score:.1f} ({self.grade}) - {self.calculated_at.strftime('%Y-%m-%d')}"


class RemediationSuggestion(models.Model):
    """Novel: Automated fix suggestions"""
    
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE, related_name='suggestions')
    
    priority = models.IntegerField(default=0)  # Higher = more important
    fix_description = models.TextField()
    code_example = models.TextField(blank=True)
    references = models.JSONField(default=list)
    estimated_effort = models.CharField(max_length=20, default='medium')  # low, medium, high
    
    class Meta:
        ordering = ['-priority']
    
    def __str__(self):
        return f"Fix for: {self.vulnerability.title}"