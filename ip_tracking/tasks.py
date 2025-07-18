from celery import shared_task
from django.utils import timezone
from django.db.models import Count
from datetime import timedelta
from .models import RequestLog, SuspiciousIP
import logging

logger = logging.getLogger(__name__)

@shared_task
def detect_suspicious_activity():
    """
    Celery task to detect suspicious IP activity.
    Runs hourly to flag IPs that:
    1. Exceed 100 requests per hour
    2. Access sensitive paths like /admin, /login
    """
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)
    
    logger.info(f"Starting anomaly detection for period: {one_hour_ago} to {now}")
    
    # Flag IPs with excessive requests (>100 per hour)
    detect_high_volume_ips(one_hour_ago, now)
    
    # Flag IPs accessing sensitive paths
    detect_sensitive_path_access(one_hour_ago, now)
    
    logger.info("Anomaly detection completed")
    return "Anomaly detection task completed successfully"

def detect_high_volume_ips(start_time, end_time):
    """Detect IPs with more than 100 requests in the last hour"""
    high_volume_ips = (
        RequestLog.objects
        .filter(timestamp__range=[start_time, end_time])
        .values('ip_address')
        .annotate(request_count=Count('ip_address'))
        .filter(request_count__gt=100)
    )
    
    for entry in high_volume_ips:
        ip = entry['ip_address']
        count = entry['request_count']
        reason = f"High volume: {count} requests in 1 hour"
        
        # Create or update suspicious IP entry
        suspicious_ip, created = SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            reason=reason,
            defaults={'is_resolved': False}
        )
        
        if created:
            logger.warning(f"Flagged suspicious IP: {ip} - {reason}")
        else:
            logger.info(f"IP {ip} already flagged for high volume")

def detect_sensitive_path_access(start_time, end_time):
    """Detect IPs accessing sensitive paths"""
    sensitive_paths = ['/admin', '/login', '/api', '/sensitive']
    
    for path in sensitive_paths:
        # Find IPs accessing sensitive paths
        sensitive_access = (
            RequestLog.objects
            .filter(
                timestamp__range=[start_time, end_time],
                path__startswith=path
            )
            .values('ip_address')
            .annotate(access_count=Count('ip_address'))
            .filter(access_count__gte=5)  # Flag if accessed 5+ times
        )
        
        for entry in sensitive_access:
            ip = entry['ip_address']
            count = entry['access_count']
            reason = f"Sensitive path access: {count} requests to {path}"
            
            # Create or update suspicious IP entry
            suspicious_ip, created = SuspiciousIP.objects.get_or_create(
                ip_address=ip,
                reason=reason,
                defaults={'is_resolved': False}
            )
            
            if created:
                logger.warning(f"Flagged suspicious IP: {ip} - {reason}")

@shared_task
def cleanup_old_logs():
    """Clean up old request logs (older than 30 days)"""
    thirty_days_ago = timezone.now() - timedelta(days=30)
    deleted_count = RequestLog.objects.filter(timestamp__lt=thirty_days_ago).delete()[0]
    logger.info(f"Cleaned up {deleted_count} old request logs")
    return f"Cleaned up {deleted_count} old logs"

@shared_task
def generate_security_report():
    """Generate a security report of flagged IPs"""
    suspicious_count = SuspiciousIP.objects.filter(is_resolved=False).count()
    recent_logs = RequestLog.objects.filter(
        timestamp__gte=timezone.now() - timedelta(hours=24)
    ).count()
    
    report = {
        'suspicious_ips': suspicious_count,
        'requests_last_24h': recent_logs,
        'timestamp': timezone.now().isoformat()
    }
    
    logger.info(f"Security report generated: {report}")
    return report