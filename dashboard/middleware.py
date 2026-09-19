from django.utils import timezone
from django.http import HttpResponseForbidden
from django.conf import settings
from django.core.cache import cache
import hashlib


class BruteForceMiddleware:
    """Protect all POST endpoints from brute force and rate limit attacks."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)

        # Check if IP is blacklisted
        from dashboard.models import BlacklistedIP
        try:
            bl = BlacklistedIP.objects.get(ip_address=ip)
            if bl.is_active:
                self._log_blocked(ip, request.path)
                return HttpResponseForbidden(
                    "<h2>Access Denied</h2>"
                    f"<p>Your IP address <strong>{ip}</strong> has been blacklisted by the Intrusion Tolerant System.</p>"
                    "<p>Contact your system administrator if you believe this is an error.</p>"
                )
        except BlacklistedIP.DoesNotExist:
            pass

        # Rate limiting: max N requests per minute
        rate_key = f'rate_{ip}'
        rate_count = cache.get(rate_key, 0)
        max_rpm = int(getattr(settings, 'ITS_RATE_LIMIT_PER_MINUTE', 30))

        if rate_count >= max_rpm:
            from dashboard.models import SecurityEvent, AuditLog
            SecurityEvent.objects.create(
                event_type='Rate Limit Exceeded',
                ip_address=ip,
                details=f'{rate_count} req/min (limit: {max_rpm})',
                severity='WARNING',
                response='Throttled'
            )
            self._audit('WARN', 'RATE', f'Rate limit exceeded: ip={ip} req_rate={rate_count}/min limit={max_rpm}/min. Throttle applied.')
            return HttpResponseForbidden("<h2>Rate Limit Exceeded</h2><p>Too many requests. Please wait before trying again.</p>")

        cache.set(rate_key, rate_count + 1, 60)
        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded:
            return x_forwarded.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '127.0.0.1')

    def _log_blocked(self, ip, path):
        from dashboard.models import AuditLog
        try:
            self._audit('CRIT', 'SEC', f'Blacklisted IP attempted access: {ip} path={path}. Request denied.')
        except Exception:
            pass

    def _audit(self, level, module, message):
        from dashboard.models import AuditLog
        try:
            AuditLog.objects.create(level=level, module=module, message=f'[{module}] {message}')
        except Exception:
            pass
