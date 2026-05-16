from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils import timezone
from datetime import timedelta
import json

from .models import (
    SecurityScan,
    Vulnerability,
    SecurityHealthScore,
    VulnerabilityCorrelation
)
from .analyzers.health_score import (
    SecurityHealthScoreCalculator,
    calculate_trend_analysis
)
from .correlators.vulnerability_correlator import VulnerabilityCorrelator
from .analyzers.prioritization import VulnerabilityPrioritizer


@login_required
def dashboard(request):
    """Main Security Intelligence Dashboard"""
    
    # Get latest health score
    latest_score = SecurityHealthScore.objects.first()
    
    # Get historical scores for trend
    historical_scores = list(
        SecurityHealthScore.objects.values(
            'overall_score',
            'calculated_at',
            'grade'
        )[:10]
    )
    
    # Calculate trend
    trend = calculate_trend_analysis(historical_scores) if historical_scores else {}
    
    # Get recent scans
    recent_scans = SecurityScan.objects.all()[:10]
    
    # Vulnerability counts by severity
    severity_counts = {
        'critical': Vulnerability.objects.filter(
            severity='critical', status='open'
        ).count(),
        'high': Vulnerability.objects.filter(
            severity='high', status='open'
        ).count(),
        'medium': Vulnerability.objects.filter(
            severity='medium', status='open'
        ).count(),
        'low': Vulnerability.objects.filter(
            severity='low', status='open'
        ).count(),
    }
    
    # Vulnerability counts by tool
    tool_counts = {}
    for scan in SecurityScan.objects.all():
        tool = scan.tool_name
        count = scan.vulnerabilities.count()
        if tool not in tool_counts:
            tool_counts[tool] = 0
        tool_counts[tool] += count
    
    # Top priority vulnerabilities
    top_vulns = Vulnerability.objects.filter(
        status='open'
    ).order_by('-calculated_risk_score')[:10]
    
    # Scan type coverage
    scan_coverage = {
        'sast': SecurityScan.objects.filter(scan_type='sast').exists(),
        'sca': SecurityScan.objects.filter(scan_type='sca').exists(),
        'dast': SecurityScan.objects.filter(scan_type='dast').exists(),
        'secret': SecurityScan.objects.filter(scan_type='secret').exists(),
        'container': SecurityScan.objects.filter(scan_type='container').exists(),
    }
    
    # Total vulnerabilities
    total_vulns = Vulnerability.objects.filter(status='open').count()
    
    context = {
        'health_score': latest_score,
        'trend': trend,
        'recent_scans': recent_scans,
        'severity_counts': severity_counts,
        'tool_counts': json.dumps(tool_counts),
        'top_vulns': top_vulns,
        'scan_coverage': scan_coverage,
        'total_vulns': total_vulns,
        'historical_scores': json.dumps([
            {
                'score': s['overall_score'],
                'date': s['calculated_at'].strftime('%Y-%m-%d'),
                'grade': s['grade']
            }
            for s in historical_scores
        ]),
    }
    
    return render(request, 'dashboard/security_dashboard.html', context)


@login_required
def vulnerability_list(request):
    """List all vulnerabilities with filtering"""
    
    severity = request.GET.get('severity', '')
    tool = request.GET.get('tool', '')
    status = request.GET.get('status', 'open')
    
    vulns = Vulnerability.objects.filter(status=status)
    
    if severity:
        vulns = vulns.filter(severity=severity)
    
    if tool:
        vulns = vulns.filter(scan__tool_name=tool)
    
    vulns = vulns.order_by('-calculated_risk_score')
    
    # Available tools for filter
    tools = SecurityScan.objects.values_list(
        'tool_name', flat=True
    ).distinct()
    
    context = {
        'vulnerabilities': vulns,
        'tools': tools,
        'selected_severity': severity,
        'selected_tool': tool,
        'selected_status': status,
        'total_count': vulns.count(),
    }
    
    return render(request, 'dashboard/vulnerability_list.html', context)


@login_required
def vulnerability_detail(request, pk):
    """Detailed view of a single vulnerability"""
    
    vuln = get_object_or_404(Vulnerability, pk=pk)
    
    # Get prioritization details
    vuln_dict = {
        'severity': vuln.severity,
        'confidence': vuln.confidence,
        'cwe_id': vuln.cwe_id,
        'first_detected': vuln.first_detected,
        'correlation_count': 0,
    }
    
    priority_info = VulnerabilityPrioritizer.calculate_priority_score(vuln_dict)
    
    # Get similar vulnerabilities
    similar_vulns = Vulnerability.objects.filter(
        severity=vuln.severity,
        status='open'
    ).exclude(pk=pk)[:5]
    
    context = {
        'vulnerability': vuln,
        'priority_info': priority_info,
        'similar_vulns': similar_vulns,
    }
    
    return render(request, 'dashboard/vulnerability_detail.html', context)


@login_required
def scan_list(request):
    """List all security scans"""
    
    scans = SecurityScan.objects.all()
    
    context = {
        'scans': scans,
    }
    
    return render(request, 'dashboard/scan_list.html', context)


@login_required
def correlation_view(request):
    """Cross-tool vulnerability correlation view"""
    
    # Get all open vulnerabilities
    vulns = list(Vulnerability.objects.filter(
        status='open'
    ).values(
        'id', 'title', 'severity', 'confidence',
        'file_path', 'line_number', 'cwe_id',
        'description', 'scan__tool_name'
    ))
    
    # Add tool_name field
    for v in vulns:
        v['tool_name'] = v.pop('scan__tool_name')
    
    # Find correlations
    correlations = VulnerabilityCorrelator.find_correlations(vulns)
    
    # Generate report
    correlation_report = VulnerabilityCorrelator.generate_correlation_report(
        correlations
    )
    
    context = {
        'correlations': correlations,
        'report': correlation_report,
        'total_raw': correlation_report.get('total_raw_findings', 0),
        'unique_issues': correlation_report.get('unique_issues', 0),
        'reduction': correlation_report.get('reduction_percentage', 0),
    }
    
    return render(request, 'dashboard/correlation_view.html', context)


# API endpoints for charts
@login_required
def api_severity_data(request):
    """API: Severity distribution data for charts"""
    
    data = {
        'labels': ['Critical', 'High', 'Medium', 'Low'],
        'data': [
            Vulnerability.objects.filter(severity='critical', status='open').count(),
            Vulnerability.objects.filter(severity='high', status='open').count(),
            Vulnerability.objects.filter(severity='medium', status='open').count(),
            Vulnerability.objects.filter(severity='low', status='open').count(),
        ],
        'colors': ['#dc3545', '#fd7e14', '#ffc107', '#6c757d']
    }
    
    return JsonResponse(data)


@login_required
def api_tool_data(request):
    """API: Tool comparison data for charts"""
    
    tools = []
    counts = []
    
    for scan in SecurityScan.objects.all():
        tool = scan.tool_name
        count = scan.vulnerabilities.count()
        if tool not in tools:
            tools.append(tool)
            counts.append(count)
        else:
            idx = tools.index(tool)
            counts[idx] += count
    
    return JsonResponse({
        'labels': tools,
        'data': counts,
    })


@login_required
def api_score_history(request):
    """API: Security score history for trend chart"""
    
    scores = SecurityHealthScore.objects.order_by('calculated_at')[:20]
    
    data = {
        'labels': [s.calculated_at.strftime('%m/%d') for s in scores],
        'scores': [s.overall_score for s in scores],
        'grades': [s.grade for s in scores],
    }
    
    return JsonResponse(data)