from django.http import HttpResponseForbidden
from django.core.cache import cache
from django.conf import settings


class BruteForceMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self._get_ip(request)

        # Skip static files and admin
        if request.path.startswith('/static/') or request.path.startswith('/admin/'):
            return self.get_response(request)

        # Check blacklist
        try:
            from dashboard.models import BlacklistedIP
            bl = BlacklistedIP.objects.get(ip_address=ip)
            if bl.is_active:
                self._audit('CRIT','SEC', f'Blacklisted IP attempted access: {ip} path={request.path}.')
                return HttpResponseForbidden(
                    f"<html><body style='font-family:sans-serif;background:#0b0f1a;color:#c8d3e8;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;'>"
                    f"<div style='text-align:center;'><h1 style='color:#ef4444;font-size:48px;'>🚫</h1>"
                    f"<h2 style='color:#e8edf8;'>Access Denied</h2>"
                    f"<p>Your IP address <code style='color:#3b82f6;'>{ip}</code> has been blacklisted by the Intrusion Tolerant System.</p>"
                    f"<p style='color:#6b7a99;font-size:12px;margin-top:16px;'>Contact your system administrator if you believe this is an error.</p></div></body></html>"
                )
        except Exception:
            pass

        # Rate limiting
        rate_key   = f'rate_{ip}'
        rate_count = cache.get(rate_key, 0)
        try:
            from dashboard.models import SystemSetting
            max_rpm = int(SystemSetting.get('rate_limit_rpm', getattr(settings,'ITS_RATE_LIMIT_PER_MINUTE',30)))
        except Exception:
            max_rpm = 30

        if rate_count >= max_rpm:
            try:
                from dashboard.models import SecurityEvent
                SecurityEvent.objects.create(
                    event_type='Rate Limit Exceeded', ip_address=ip,
                    details=f'{rate_count} req/min (limit: {max_rpm})',
                    severity='WARNING', response='Throttled'
                )
                self._audit('WARN','RATE', f'Rate limit exceeded: ip={ip} req_rate={rate_count}/min limit={max_rpm}/min.')
            except Exception:
                pass
            return HttpResponseForbidden("<h2>Rate Limit Exceeded</h2><p>Too many requests. Please wait before trying again.</p>")

        cache.set(rate_key, rate_count + 1, 60)
        return self.get_response(request)

    def _get_ip(self, request):
        x = request.META.get('HTTP_X_FORWARDED_FOR')
        return x.split(',')[0].strip() if x else request.META.get('REMOTE_ADDR','127.0.0.1')

    def _audit(self, level, module, message):
        try:
            from dashboard.models import AuditLog
            AuditLog.objects.create(level=level, module=module, message=f'[{module}] {message}')
        except Exception:
            pass
