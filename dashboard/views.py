from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.http import JsonResponse, HttpResponseRedirect
from django.utils import timezone
from django.core.cache import cache
from django.conf import settings
from django.db.models import Count, Q
from datetime import timedelta
import json

from .models import LoginAttempt, BlacklistedIP, SecurityEvent, AuditLog, SystemSetting


def get_client_ip(request):
    x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded:
        return x_forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '127.0.0.1')


def audit(level, module, message):
    AuditLog.objects.create(level=level, module=module, message=f'[{module}] {message}')


def index_redirect(request):
    return redirect('dashboard') if request.user.is_authenticated else redirect('login')


# ── AUTH ─────────────────────────────────────────────────────────────
def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    error = None
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        ip = get_client_ip(request)
        max_fails = int(SystemSetting.get('max_failed_attempts', getattr(settings, 'ITS_MAX_FAILED_ATTEMPTS', 5)))

        # Count recent failures from this IP
        cutoff = timezone.now() - timedelta(minutes=15)
        ip_failures = LoginAttempt.objects.filter(
            ip_address=ip, status='FAILED', timestamp__gte=cutoff
        ).count()

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            LoginAttempt.objects.create(
                username=username, ip_address=ip, status='SUCCESS',
                action='ALLOWED', attempts_from_ip=ip_failures+1,
                user_agent=request.META.get('HTTP_USER_AGENT','')
            )
            audit('OK', 'AUTH', f'Successful login: user={username} ip={ip} session={request.session.session_key}')
            return redirect('dashboard')
        else:
            new_count = ip_failures + 1
            action = 'MONITORED'

            if new_count >= max_fails:
                # Auto-blacklist
                duration_hours = int(SystemSetting.get('blacklist_duration_hours', getattr(settings, 'ITS_BLACKLIST_DURATION_HOURS', 24)))
                expires = timezone.now() + timedelta(hours=duration_hours)
                BlacklistedIP.objects.get_or_create(
                    ip_address=ip,
                    defaults={
                        'reason': 'BRUTE_FORCE',
                        'failed_attempts': new_count,
                        'source': 'AUTO',
                        'expires_at': expires,
                        'is_permanent': duration_hours == 0,
                    }
                )
                SecurityEvent.objects.create(
                    event_type='Brute Force',
                    ip_address=ip,
                    details=f'{new_count} failed attempts in 15 min. Threshold: {max_fails}.',
                    severity='CRITICAL',
                    response='Auto-Blacklisted'
                )
                audit('CRIT', 'AUTH', f'Brute force detected: {ip} — {new_count} failures. Auto-blacklist applied. Duration: {duration_hours}h.')
                action = 'BLACKLISTED'
                error = 'Too many failed attempts. Your IP has been blacklisted.'
            elif new_count >= max(2, max_fails - 2):
                SecurityEvent.objects.create(
                    event_type='Failed Login',
                    ip_address=ip,
                    details=f'{new_count} failed attempts. Approaching threshold ({max_fails}).',
                    severity='WARNING',
                    response='Flagged'
                )
                audit('WARN', 'AUTH', f'Failed login: user={username} ip={ip} attempt={new_count} reason=invalid_password. Threshold approaching.')
                action = 'FLAGGED'
                error = f'Invalid credentials. Warning: {max_fails - new_count} attempt(s) remaining before lockout.'
            else:
                audit('INFO', 'AUTH', f'Failed login: user={username} ip={ip} attempt={new_count} reason=invalid_password.')
                error = 'Invalid username or password.'

            LoginAttempt.objects.create(
                username=username, ip_address=ip, status='FAILED',
                action=action, attempts_from_ip=new_count,
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )

    return render(request, 'dashboard/login.html', {'error': error})


def logout_view(request):
    username = request.user.username if request.user.is_authenticated else 'unknown'
    ip = get_client_ip(request)
    audit('INFO', 'AUTH', f'User logged out: user={username} ip={ip}')
    logout(request)
    return redirect('login')


# ── DASHBOARD ─────────────────────────────────────────────────────────
@login_required
def dashboard(request):
    now = timezone.now()
    day_ago = now - timedelta(hours=24)
    week_ago = now - timedelta(days=7)

    total_attempts = LoginAttempt.objects.filter(timestamp__gte=day_ago).count()
    failed_attempts = LoginAttempt.objects.filter(timestamp__gte=day_ago, status='FAILED').count()
    blacklisted_count = BlacklistedIP.objects.count()
    active_sessions = 1  # current admin session

    # Chart data: last 7 days
    chart_data = []
    for i in range(6, -1, -1):
        day_start = now - timedelta(days=i+1)
        day_end = now - timedelta(days=i)
        day_label = day_start.strftime('%a')
        ok = LoginAttempt.objects.filter(timestamp__gte=day_start, timestamp__lt=day_end, status='SUCCESS').count()
        fail = LoginAttempt.objects.filter(timestamp__gte=day_start, timestamp__lt=day_end, status='FAILED').count()
        chart_data.append({'day': day_label, 'ok': ok, 'fail': fail})

    # Threat breakdown
    total_events = SecurityEvent.objects.filter(timestamp__gte=week_ago).count() or 1
    brute_pct = round(SecurityEvent.objects.filter(timestamp__gte=week_ago, event_type='Brute Force').count() / total_events * 100)
    rate_pct = round(SecurityEvent.objects.filter(timestamp__gte=week_ago, event_type='Rate Limit Exceeded').count() / total_events * 100)
    other_pct = 100 - brute_pct - rate_pct

    recent_events = SecurityEvent.objects.all()[:8]
    recent_logs = LoginAttempt.objects.all()[:5]

    return render(request, 'dashboard/dashboard.html', {
        'page': 'dashboard',
        'total_attempts': total_attempts,
        'failed_attempts': failed_attempts,
        'blacklisted_count': blacklisted_count,
        'active_sessions': active_sessions,
        'chart_data': json.dumps(chart_data),
        'brute_pct': brute_pct,
        'rate_pct': rate_pct,
        'other_pct': other_pct,
        'recent_events': recent_events,
        'recent_logs': recent_logs,
    })


@login_required
def login_logs(request):
    q = request.GET.get('q', '')
    logs = LoginAttempt.objects.all()
    if q:
        logs = logs.filter(Q(ip_address__icontains=q) | Q(username__icontains=q))

    day_ago = timezone.now() - timedelta(hours=24)
    total_24h = LoginAttempt.objects.filter(timestamp__gte=day_ago).count()
    failed_24h = LoginAttempt.objects.filter(timestamp__gte=day_ago, status='FAILED').count()
    unique_ips = LoginAttempt.objects.filter(timestamp__gte=day_ago).values('ip_address').distinct().count()

    return render(request, 'dashboard/login_logs.html', {
        'page': 'login_logs',
        'logs': logs[:100],
        'q': q,
        'total_24h': total_24h,
        'failed_24h': failed_24h,
        'unique_ips': unique_ips,
    })


@login_required
def blacklist(request):
    entries = BlacklistedIP.objects.all()
    auto_count = entries.filter(source='AUTO').count()
    return render(request, 'dashboard/blacklist.html', {
        'page': 'blacklist',
        'entries': entries,
        'total': entries.count(),
        'auto_count': auto_count,
    })


@login_required
@require_POST
def blacklist_add(request):
    ip = request.POST.get('ip', '').strip()
    notes = request.POST.get('notes', '')
    if not ip:
        return redirect('blacklist')
    obj, created = BlacklistedIP.objects.get_or_create(
        ip_address=ip,
        defaults={'reason': 'MANUAL', 'source': 'MANUAL', 'is_permanent': True, 'notes': notes}
    )
    if created:
        ip_addr = get_client_ip(request)
        audit('INFO', 'SEC', f'Manual IP block applied by admin ({request.user.username}): {ip}. Block: permanent.')
    return redirect('blacklist')


@login_required
def blacklist_remove(request, pk):
    entry = get_object_or_404(BlacklistedIP, pk=pk)
    ip = entry.ip_address
    entry.delete()
    audit('INFO', 'SEC', f'IP unblocked by admin ({request.user.username}): {ip}. Block removed.')
    return redirect('blacklist')


@login_required
def events(request):
    sev = request.GET.get('sev', '')
    evs = SecurityEvent.objects.all()
    if sev:
        evs = evs.filter(severity=sev)

    alerts = SecurityEvent.objects.filter(severity__in=['CRITICAL', 'WARNING'])[:3]
    return render(request, 'dashboard/events.html', {
        'page': 'events',
        'events': evs[:100],
        'alerts': alerts,
        'sev': sev,
    })


@login_required
def rate_limits(request):
    rpm = SystemSetting.get('rate_limit_rpm', getattr(settings, 'ITS_RATE_LIMIT_PER_MINUTE', 30))
    max_fails = SystemSetting.get('max_failed_attempts', getattr(settings, 'ITS_MAX_FAILED_ATTEMPTS', 5))
    lockout = SystemSetting.get('lockout_minutes', getattr(settings, 'ITS_LOCKOUT_MINUTES', 15))
    window = SystemSetting.get('rate_window_seconds', 60)
    burst = SystemSetting.get('burst_allowance', 10)

    rate_events = SecurityEvent.objects.filter(event_type='Rate Limit Exceeded')[:20]
    return render(request, 'dashboard/rate_limits.html', {
        'page': 'rate_limits',
        'rpm': rpm, 'max_fails': max_fails,
        'lockout': lockout, 'window': window, 'burst': burst,
        'rate_events': rate_events,
    })


@login_required
@require_POST
def rate_limits_save(request):
    fields = ['rate_limit_rpm','max_failed_attempts','lockout_minutes','rate_window_seconds','burst_allowance']
    for f in fields:
        val = request.POST.get(f)
        if val:
            SystemSetting.set(f, val)
    audit('INFO', 'CFG', f'Rate limit thresholds updated by {request.user.username}: ' + ', '.join(f'{k}={request.POST.get(k)}' for k in fields if request.POST.get(k)))
    return redirect('rate_limits')


@login_required
def audit_logs(request):
    q = request.GET.get('q', '')
    level = request.GET.get('level', '')
    logs = AuditLog.objects.all()
    if q:
        logs = logs.filter(message__icontains=q)
    if level:
        logs = logs.filter(level=level)
    return render(request, 'dashboard/audit.html', {
        'page': 'audit',
        'logs': logs[:200],
        'q': q,
        'level': level,
    })


@login_required
def settings_view(request):
    s = {
        'max_failed_attempts': SystemSetting.get('max_failed_attempts', 5),
        'detection_window': SystemSetting.get('detection_window_seconds', 300),
        'blacklist_duration_hours': SystemSetting.get('blacklist_duration_hours', 24),
        'rate_limit_rpm': SystemSetting.get('rate_limit_rpm', 30),
        'burst_allowance': SystemSetting.get('burst_allowance', 10),
        'alert_email': SystemSetting.get('alert_email', 'admin@its-cloud.local'),
        'log_retention_days': SystemSetting.get('log_retention_days', 90),
        'brute_force_enabled': SystemSetting.get('brute_force_enabled', 'true'),
        'rate_limit_enabled': SystemSetting.get('rate_limit_enabled', 'true'),
        'email_critical': SystemSetting.get('email_critical', 'true'),
        'email_warning': SystemSetting.get('email_warning', 'true'),
        'audit_enabled': SystemSetting.get('audit_enabled', 'true'),
        'log_all_logins': SystemSetting.get('log_all_logins', 'true'),
    }
    return render(request, 'dashboard/settings.html', {'page': 'settings', 's': s})


@login_required
@require_POST
def settings_save(request):
    fields = [
        'max_failed_attempts','detection_window_seconds','blacklist_duration_hours',
        'rate_limit_rpm','burst_allowance','alert_email','log_retention_days',
    ]
    for f in fields:
        val = request.POST.get(f)
        if val is not None:
            SystemSetting.set(f, val)
    toggles = ['brute_force_enabled','rate_limit_enabled','email_critical','email_warning','audit_enabled','log_all_logins']
    for t in toggles:
        SystemSetting.set(t, 'true' if request.POST.get(t) else 'false')
    audit('INFO', 'CFG', f'System settings updated by {request.user.username}. All parameters applied.')
    return redirect('settings')


@login_required
def api_stats(request):
    now = timezone.now()
    day_ago = now - timedelta(hours=24)
    return JsonResponse({
        'total_attempts': LoginAttempt.objects.filter(timestamp__gte=day_ago).count(),
        'failed_attempts': LoginAttempt.objects.filter(timestamp__gte=day_ago, status='FAILED').count(),
        'blacklisted_count': BlacklistedIP.objects.count(),
        'critical_events': SecurityEvent.objects.filter(severity='CRITICAL', timestamp__gte=day_ago).count(),
    })
