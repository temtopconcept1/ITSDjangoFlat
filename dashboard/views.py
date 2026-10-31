from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.db.models import Count, Q
from django.conf import settings
from datetime import timedelta
from functools import wraps
import json, csv, io

from .models import (LoginAttempt, BlacklistedIP, SecurityEvent,
                     AuditLog, SystemSetting, UserProfile, UserSession)


# ── HELPERS ───────────────────────────────────────────────────────
def get_ip(request):
    x = request.META.get('HTTP_X_FORWARDED_FOR')
    return x.split(',')[0].strip() if x else request.META.get('REMOTE_ADDR','127.0.0.1')

def audit(level, module, message, user=None):
    AuditLog.objects.create(level=level, module=module, message=f'[{module}] {message}', performed_by=user)

def ensure_profile(user):
    profile, created = UserProfile.objects.get_or_create(user=user)
    if created:
        profile.role   = 'ADMIN' if user.is_superuser else 'VIEWER'
        profile.status = 'ACTIVE'
        profile.save()
    return profile

def admin_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        profile = ensure_profile(request.user)
        if profile.role != 'ADMIN' and not request.user.is_superuser:
            return render(request, 'dashboard/403.html', status=403)
        return view_func(request, *args, **kwargs)
    return wrapper

def analyst_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        profile = ensure_profile(request.user)
        if profile.role not in ('ADMIN','ANALYST') and not request.user.is_superuser:
            return render(request, 'dashboard/403.html', status=403)
        return view_func(request, *args, **kwargs)
    return wrapper

def index_redirect(request):
    return redirect('dashboard') if request.user.is_authenticated else redirect('login')


# ── REGISTER ──────────────────────────────────────────────────────
def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    error = None
    if request.method == 'POST':
        username   = request.POST.get('username','').strip()
        email      = request.POST.get('email','').strip()
        first_name = request.POST.get('first_name','').strip()
        last_name  = request.POST.get('last_name','').strip()
        department = request.POST.get('department','').strip()
        password   = request.POST.get('password','')
        password2  = request.POST.get('password2','')
        ip         = get_ip(request)

        if not all([username, email, first_name, last_name, password]):
            error = 'All fields are required.'
        elif password != password2:
            error = 'Passwords do not match.'
        elif len(password) < 8:
            error = 'Password must be at least 8 characters.'
        elif User.objects.filter(username=username).exists():
            error = 'Username already taken.'
        elif User.objects.filter(email=email).exists():
            error = 'Email already registered.'
        else:
            user = User.objects.create_user(
                username=username, email=email, password=password,
                first_name=first_name, last_name=last_name,
                is_active=False  # Cannot login until approved
            )
            profile = UserProfile.objects.create(
                user=user, role='VIEWER', status='PENDING',
                department=department, known_ips=ip
            )
            audit('INFO','AUTH', f'New user registration: {username} ({email}) from {ip}. Awaiting admin approval.')
            SecurityEvent.objects.create(
                event_type='New Registration', ip_address=ip,
                details=f'User {username} registered. Pending admin approval.',
                severity='INFO', response='Awaiting Approval'
            )
            return render(request, 'dashboard/register_success.html', {'username': username})

    return render(request, 'dashboard/register.html', {'error': error})


# ── LOGIN ─────────────────────────────────────────────────────────
def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    error = None
    if request.method == 'POST':
        username = request.POST.get('username','').strip()
        password = request.POST.get('password','')
        ip       = get_ip(request)
        max_fails = int(SystemSetting.get('max_failed_attempts', 5))
        cutoff    = timezone.now() - timedelta(minutes=15)
        ip_fails  = LoginAttempt.objects.filter(ip_address=ip, status='FAILED', timestamp__gte=cutoff).count()

        user = authenticate(request, username=username, password=password)

        if user is not None:
            profile = ensure_profile(user)

            if profile.status == 'PENDING':
                error = 'Your account is pending admin approval. You will be notified once approved.'
                LoginAttempt.objects.create(username=username, ip_address=ip, status='FAILED', action='PENDING', user=user)
                audit('WARN','AUTH', f'Login blocked — account pending approval: {username} from {ip}')
            elif profile.status == 'SUSPENDED':
                error = 'Your account has been suspended. Contact your administrator.'
                LoginAttempt.objects.create(username=username, ip_address=ip, status='FAILED', action='SUSPENDED', user=user)
                audit('WARN','AUTH', f'Login blocked — account suspended: {username} from {ip}')
            elif profile.status == 'REJECTED':
                error = 'Your registration was not approved. Contact your administrator.'
            else:
                # Successful login
                login(request, user)
                is_new_ip = profile.add_known_ip(ip)
                profile.last_seen = timezone.now()
                profile.save()

                # Track session
                UserSession.objects.filter(user=user, session_key=request.session.session_key).delete()
                UserSession.objects.create(
                    user=user, session_key=request.session.session_key,
                    ip_address=ip, user_agent=request.META.get('HTTP_USER_AGENT',''),
                    is_new_ip=is_new_ip
                )

                LoginAttempt.objects.create(
                    username=username, ip_address=ip, status='SUCCESS',
                    action='NEW_IP' if is_new_ip else 'ALLOWED',
                    user=user, is_new_ip=is_new_ip,
                    user_agent=request.META.get('HTTP_USER_AGENT','')
                )

                if is_new_ip:
                    SecurityEvent.objects.create(
                        event_type='New IP Login', ip_address=ip,
                        details=f'User {username} logged in from new IP: {ip}',
                        severity='WARNING', response='Flagged', user=user
                    )
                    audit('WARN','AUTH', f'New IP login: user={username} ip={ip} — first time from this address.', user)
                else:
                    audit('OK','AUTH', f'Successful login: user={username} ip={ip} session={request.session.session_key}', user)

                return redirect('dashboard')
        else:
            new_count = ip_fails + 1
            action = 'MONITORED'
            if new_count >= max_fails:
                dur = int(SystemSetting.get('blacklist_duration_hours', 24))
                BlacklistedIP.objects.get_or_create(
                    ip_address=ip,
                    defaults={'reason':'BRUTE_FORCE','failed_attempts':new_count,'source':'AUTO',
                              'expires_at': timezone.now()+timedelta(hours=dur) if dur else None,
                              'is_permanent': dur==0}
                )
                SecurityEvent.objects.create(
                    event_type='Brute Force', ip_address=ip,
                    details=f'{new_count} failed attempts. Threshold: {max_fails}.',
                    severity='CRITICAL', response='Auto-Blacklisted'
                )
                audit('CRIT','AUTH', f'Brute force: {ip} — {new_count} failures. Auto-blacklisted.')
                action  = 'BLACKLISTED'
                error   = f'Too many failed attempts. Your IP has been blocked.'
            elif new_count >= max(2, max_fails - 2):
                action = 'FLAGGED'
                rem    = max_fails - new_count
                error  = f'Invalid credentials. {rem} attempt(s) remaining before lockout.'
                audit('WARN','AUTH', f'Failed login: user={username} ip={ip} attempt={new_count}. Threshold approaching.')
            else:
                error = 'Invalid username or password.'
                audit('INFO','AUTH', f'Failed login: user={username} ip={ip} attempt={new_count}.')

            LoginAttempt.objects.create(username=username, ip_address=ip, status='FAILED', action=action,
                                        attempts_from_ip=new_count, user_agent=request.META.get('HTTP_USER_AGENT',''))

    return render(request, 'dashboard/login.html', {'error': error})


def logout_view(request):
    if request.user.is_authenticated:
        UserSession.objects.filter(user=request.user, session_key=request.session.session_key).update(is_active=False)
        audit('INFO','AUTH', f'User logged out: {request.user.username}', request.user)
    logout(request)
    return redirect('login')


# ── DASHBOARD ─────────────────────────────────────────────────────
@login_required
def dashboard(request):
    ensure_profile(request.user)
    now     = timezone.now()
    day_ago = now - timedelta(hours=24)
    week_ago= now - timedelta(days=7)

    total_attempts  = LoginAttempt.objects.filter(timestamp__gte=day_ago).count()
    failed_attempts = LoginAttempt.objects.filter(timestamp__gte=day_ago, status='FAILED').count()
    blacklisted_count = BlacklistedIP.objects.count()
    active_sessions = UserSession.objects.filter(is_active=True).count()
    pending_users   = UserProfile.objects.filter(status='PENDING').count()

    total_ev = SecurityEvent.objects.filter(timestamp__gte=week_ago).count() or 1
    brute_pct = round(SecurityEvent.objects.filter(timestamp__gte=week_ago, event_type='Brute Force').count()/total_ev*100)
    rate_pct  = round(SecurityEvent.objects.filter(timestamp__gte=week_ago, event_type='Rate Limit Exceeded').count()/total_ev*100)
    other_pct = max(0, 100-brute_pct-rate_pct)

    recent_events = SecurityEvent.objects.select_related('user').all()[:8]

    return render(request, 'dashboard/dashboard.html', {
        'page':'dashboard',
        'total_attempts': total_attempts, 'failed_attempts': failed_attempts,
        'blacklisted_count': blacklisted_count, 'active_sessions': active_sessions,
        'pending_users': pending_users,
        'brute_pct': brute_pct, 'rate_pct': rate_pct, 'other_pct': other_pct,
        'recent_events': recent_events,
    })


@login_required
def api_chart(request):
    """Login attempts bucketed by Lagos (WAT) calendar day or hour, from real DB records."""
    from django.db.models.functions import TruncDay, TruncHour
    rng  = request.GET.get('range', '7d')
    tz   = timezone.get_current_timezone()          # Africa/Lagos
    now  = timezone.localtime()
    if rng == '24h':
        end     = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        starts  = [end - timedelta(hours=24 - i) for i in range(24)]
        trunc   = TruncHour('timestamp', tzinfo=tz)
        fmt     = lambda d: (d.strftime('%H:00'), d.strftime('%d %b, %H:00') + ' WAT')
        range_start, range_end = starts[0], end
    else:
        today   = now.replace(hour=0, minute=0, second=0, microsecond=0)
        starts  = [today - timedelta(days=6 - i) for i in range(7)]
        trunc   = TruncDay('timestamp', tzinfo=tz)
        fmt     = lambda d: (d.strftime('%a'), d.strftime('%a %d %b'))
        range_start, range_end = starts[0], today + timedelta(days=1)

    rows = (LoginAttempt.objects
            .filter(timestamp__gte=range_start, timestamp__lt=range_end)
            .annotate(b=trunc).values('b')
            .annotate(ok=Count('id', filter=Q(status='SUCCESS')),
                      fail=Count('id', filter=Q(status='FAILED'))))
    found = {r['b']: r for r in rows}

    data = []
    for st in starts:
        r = found.get(st, {})
        label, full = fmt(st)
        data.append({'day': label, 'date': full, 'ok': r.get('ok', 0), 'fail': r.get('fail', 0)})
    return JsonResponse({
        'data': data, 'range': rng, 'timezone': 'WAT (UTC+1)',
        'now': now.strftime('%d %b %Y, %H:%M:%S'),
        'total_ok': sum(d['ok'] for d in data), 'total_fail': sum(d['fail'] for d in data),
    })


@login_required
def api_stats(request):
    now     = timezone.now()
    day_ago = now - timedelta(hours=24)
    return JsonResponse({
        'total_attempts':   LoginAttempt.objects.filter(timestamp__gte=day_ago).count(),
        'failed_attempts':  LoginAttempt.objects.filter(timestamp__gte=day_ago, status='FAILED').count(),
        'blacklisted_count':BlacklistedIP.objects.count(),
        'active_sessions':  UserSession.objects.filter(is_active=True).count(),
        'pending_users':    UserProfile.objects.filter(status='PENDING').count(),
        'critical_events':  SecurityEvent.objects.filter(severity='CRITICAL', timestamp__gte=day_ago).count(),
    })


# ── LOGIN LOGS ────────────────────────────────────────────────────
@login_required
@analyst_required
def login_logs(request):
    q    = request.GET.get('q','')
    logs = LoginAttempt.objects.select_related('user').all()
    if q:
        logs = logs.filter(Q(ip_address__icontains=q)|Q(username__icontains=q))
    day_ago  = timezone.now()-timedelta(hours=24)
    total_24h  = LoginAttempt.objects.filter(timestamp__gte=day_ago).count()
    failed_24h = LoginAttempt.objects.filter(timestamp__gte=day_ago, status='FAILED').count()
    unique_ips = LoginAttempt.objects.filter(timestamp__gte=day_ago).values('ip_address').distinct().count()
    new_ip_count = LoginAttempt.objects.filter(timestamp__gte=day_ago, is_new_ip=True).count()
    return render(request, 'dashboard/login_logs.html', {
        'page':'login_logs','logs':logs[:200],'q':q,
        'total_24h':total_24h,'failed_24h':failed_24h,
        'unique_ips':unique_ips,'new_ip_count':new_ip_count,
    })


# ── BLACKLIST ─────────────────────────────────────────────────────
@login_required
@analyst_required
def blacklist(request):
    entries    = BlacklistedIP.objects.all()
    auto_count = entries.filter(source='AUTO').count()
    return render(request, 'dashboard/blacklist.html', {
        'page':'blacklist','entries':entries,
        'total':entries.count(),'auto_count':auto_count,
    })

@login_required
@analyst_required
@require_POST
def blacklist_add(request):
    ip    = request.POST.get('ip','').strip()
    notes = request.POST.get('notes','')
    if ip:
        obj, created = BlacklistedIP.objects.get_or_create(
            ip_address=ip,
            defaults={'reason':'MANUAL','source':'MANUAL','is_permanent':True,'notes':notes,'added_by':request.user}
        )
        if created:
            audit('INFO','SEC', f'Manual IP block: {ip} by {request.user.username}.', request.user)
    return redirect('blacklist')

@login_required
@admin_required
def blacklist_remove(request, pk):
    entry = get_object_or_404(BlacklistedIP, pk=pk)
    ip    = entry.ip_address
    entry.delete()
    audit('INFO','SEC', f'IP unblocked: {ip} by {request.user.username}.', request.user)
    return redirect('blacklist')


# ── EVENTS ────────────────────────────────────────────────────────
@login_required
@analyst_required
def events(request):
    sev    = request.GET.get('sev','')
    evs    = SecurityEvent.objects.select_related('user').all()
    if sev:
        evs = evs.filter(severity=sev)
    alerts = SecurityEvent.objects.filter(severity__in=['CRITICAL','WARNING'])[:3]
    return render(request, 'dashboard/events.html', {
        'page':'events','events':evs[:150],'alerts':alerts,'sev':sev,
    })


# ── RATE LIMITS ───────────────────────────────────────────────────
@login_required
@analyst_required
def rate_limits(request):
    rpm      = SystemSetting.get('rate_limit_rpm', 30)
    max_fails= SystemSetting.get('max_failed_attempts', 5)
    lockout  = SystemSetting.get('lockout_minutes', 15)
    window   = SystemSetting.get('rate_window_seconds', 60)
    burst    = SystemSetting.get('burst_allowance', 10)
    rate_events = SecurityEvent.objects.filter(event_type='Rate Limit Exceeded')[:20]
    return render(request, 'dashboard/rate_limits.html', {
        'page':'rate_limits','rpm':rpm,'max_fails':max_fails,
        'lockout':lockout,'window':window,'burst':burst,'rate_events':rate_events,
    })

@login_required
@admin_required
@require_POST
def rate_limits_save(request):
    for f in ['rate_limit_rpm','max_failed_attempts','lockout_minutes','rate_window_seconds','burst_allowance']:
        if request.POST.get(f):
            SystemSetting.set(f, request.POST[f])
    audit('INFO','CFG', f'Rate limits updated by {request.user.username}.', request.user)
    return redirect('rate_limits')


# ── AUDIT LOGS ────────────────────────────────────────────────────
@login_required
@analyst_required
def audit_logs(request):
    q     = request.GET.get('q','')
    level = request.GET.get('level','')
    logs  = AuditLog.objects.select_related('performed_by').all()
    if q:
        logs = logs.filter(message__icontains=q)
    if level:
        logs = logs.filter(level=level)
    return render(request, 'dashboard/audit.html', {
        'page':'audit','logs':logs[:300],'q':q,'level':level,
    })


# ── SETTINGS ──────────────────────────────────────────────────────
@login_required
@admin_required
def settings_view(request):
    s = {
        'max_failed_attempts':     SystemSetting.get('max_failed_attempts',5),
        'detection_window':        SystemSetting.get('detection_window_seconds',300),
        'blacklist_duration_hours':SystemSetting.get('blacklist_duration_hours',24),
        'rate_limit_rpm':          SystemSetting.get('rate_limit_rpm',30),
        'burst_allowance':         SystemSetting.get('burst_allowance',10),
        'alert_email':             SystemSetting.get('alert_email','admin@its-cloud.local'),
        'log_retention_days':      SystemSetting.get('log_retention_days',90),
        'brute_force_enabled':     SystemSetting.get('brute_force_enabled','true'),
        'rate_limit_enabled':      SystemSetting.get('rate_limit_enabled','true'),
        'email_critical':          SystemSetting.get('email_critical','true'),
        'email_warning':           SystemSetting.get('email_warning','true'),
        'audit_enabled':           SystemSetting.get('audit_enabled','true'),
        'log_all_logins':          SystemSetting.get('log_all_logins','true'),
        'require_approval':        SystemSetting.get('require_approval','true'),
    }
    return render(request, 'dashboard/settings.html', {'page':'settings','s':s})

@login_required
@admin_required
@require_POST
def settings_save(request):
    for f in ['max_failed_attempts','detection_window_seconds','blacklist_duration_hours',
              'rate_limit_rpm','burst_allowance','alert_email','log_retention_days']:
        if request.POST.get(f) is not None:
            SystemSetting.set(f, request.POST[f])
    for t in ['brute_force_enabled','rate_limit_enabled','email_critical','email_warning',
              'audit_enabled','log_all_logins','require_approval']:
        SystemSetting.set(t, 'true' if request.POST.get(t) else 'false')
    audit('INFO','CFG', f'System settings updated by {request.user.username}.', request.user)
    return redirect('settings')


# ── USER MANAGEMENT ───────────────────────────────────────────────
@login_required
@admin_required
def user_list(request):
    status = request.GET.get('status','')
    users  = UserProfile.objects.select_related('user','approved_by').all()
    if status:
        users = users.filter(status=status)
    pending_count  = UserProfile.objects.filter(status='PENDING').count()
    active_count   = UserProfile.objects.filter(status='ACTIVE').count()
    suspended_count= UserProfile.objects.filter(status='SUSPENDED').count()
    return render(request, 'dashboard/users.html', {
        'page':'users','users':users,'status':status,
        'pending_count':pending_count,'active_count':active_count,'suspended_count':suspended_count,
    })

@login_required
@admin_required
@require_POST
def user_approve(request, pk):
    profile = get_object_or_404(UserProfile, pk=pk)
    role    = request.POST.get('role','VIEWER')
    profile.status      = 'ACTIVE'
    profile.role        = role
    profile.approved_at = timezone.now()
    profile.approved_by = request.user
    profile.save()
    profile.user.is_active = True
    profile.user.save()
    audit('OK','USR', f'User approved: {profile.user.username} as {role} by {request.user.username}.', request.user)
    SecurityEvent.objects.create(
        event_type='User Approved', ip_address='0.0.0.0',
        details=f'{profile.user.username} approved as {role} by {request.user.username}',
        severity='INFO', response='Account Activated'
    )
    return redirect('user_list')

@login_required
@admin_required
def user_reject(request, pk):
    profile = get_object_or_404(UserProfile, pk=pk)
    profile.status = 'REJECTED'
    profile.save()
    audit('INFO','USR', f'User rejected: {profile.user.username} by {request.user.username}.', request.user)
    return redirect('user_list')

@login_required
@admin_required
def user_suspend(request, pk):
    profile = get_object_or_404(UserProfile, pk=pk)
    profile.status = 'SUSPENDED'
    profile.save()
    profile.user.is_active = False
    profile.user.save()
    UserSession.objects.filter(user=profile.user).update(is_active=False)
    audit('WARN','USR', f'User suspended: {profile.user.username} by {request.user.username}.', request.user)
    return redirect('user_list')

@login_required
@admin_required
def user_activate(request, pk):
    profile = get_object_or_404(UserProfile, pk=pk)
    profile.status = 'ACTIVE'
    profile.save()
    profile.user.is_active = True
    profile.user.save()
    audit('OK','USR', f'User re-activated: {profile.user.username} by {request.user.username}.', request.user)
    return redirect('user_list')

@login_required
@admin_required
def user_delete(request, pk):
    profile = get_object_or_404(UserProfile, pk=pk)
    username = profile.user.username
    profile.user.delete()
    audit('WARN','USR', f'User deleted: {username} by {request.user.username}.', request.user)
    return redirect('user_list')

@login_required
@admin_required
@require_POST
def user_role(request, pk):
    profile = get_object_or_404(UserProfile, pk=pk)
    role    = request.POST.get('role','VIEWER')
    old     = profile.role
    profile.role = role
    profile.save()
    audit('INFO','USR', f'Role changed: {profile.user.username} {old}→{role} by {request.user.username}.', request.user)
    return redirect('user_list')


# ── SESSIONS ──────────────────────────────────────────────────────
@login_required
@admin_required
def sessions_view(request):
    sessions = UserSession.objects.select_related('user').filter(is_active=True)
    return render(request, 'dashboard/sessions.html', {
        'page':'sessions','sessions':sessions,
    })

@login_required
@admin_required
def session_kill(request, pk):
    sess = get_object_or_404(UserSession, pk=pk)
    sess.is_active = False
    sess.save()
    audit('WARN','SEC', f'Session killed: {sess.user.username} @ {sess.ip_address} by {request.user.username}.', request.user)
    return redirect('sessions')


# ── PROFILE ───────────────────────────────────────────────────────
@login_required
def profile_view(request):
    profile  = ensure_profile(request.user)
    sessions = UserSession.objects.filter(user=request.user).order_by('-created_at')[:10]
    return render(request, 'dashboard/profile.html', {
        'page':'profile','profile':profile,'sessions':sessions,
    })

@login_required
@require_POST
def profile_save(request):
    user    = request.user
    profile = ensure_profile(user)
    user.first_name = request.POST.get('first_name', user.first_name)
    user.last_name  = request.POST.get('last_name',  user.last_name)
    user.email      = request.POST.get('email',      user.email)
    user.save()
    profile.phone      = request.POST.get('phone','')
    profile.department = request.POST.get('department','')
    profile.bio        = request.POST.get('bio','')
    profile.save()
    audit('INFO','USR', f'Profile updated: {user.username}.', user)
    return redirect('profile')

@login_required
@require_POST
def change_password(request):
    old_pass = request.POST.get('old_password','')
    new_pass = request.POST.get('new_password','')
    confirm  = request.POST.get('confirm_password','')
    profile  = ensure_profile(request.user)
    error    = None
    if not request.user.check_password(old_pass):
        error = 'Current password is incorrect.'
    elif new_pass != confirm:
        error = 'New passwords do not match.'
    elif len(new_pass) < 8:
        error = 'Password must be at least 8 characters.'
    else:
        request.user.set_password(new_pass)
        request.user.save()
        update_session_auth_hash(request, request.user)
        audit('OK','AUTH', f'Password changed: {request.user.username}.', request.user)
        return redirect('profile')
    sessions = UserSession.objects.filter(user=request.user).order_by('-created_at')[:10]
    return render(request, 'dashboard/profile.html', {
        'page':'profile','profile':profile,'sessions':sessions,'pw_error':error,
    })


# ── REPORTS ───────────────────────────────────────────────────────
@login_required
@analyst_required
def reports_view(request):
    now      = timezone.now()
    day_ago  = now - timedelta(hours=24)
    week_ago = now - timedelta(days=7)
    return render(request, 'dashboard/reports.html', {
        'page':'reports',
        'total_logins':    LoginAttempt.objects.filter(timestamp__gte=week_ago).count(),
        'failed_logins':   LoginAttempt.objects.filter(timestamp__gte=week_ago, status='FAILED').count(),
        'total_events':    SecurityEvent.objects.filter(timestamp__gte=week_ago).count(),
        'critical_events': SecurityEvent.objects.filter(timestamp__gte=week_ago, severity='CRITICAL').count(),
        'blacklisted':     BlacklistedIP.objects.count(),
        'active_users':    UserProfile.objects.filter(status='ACTIVE').count(),
        'new_ips':         LoginAttempt.objects.filter(timestamp__gte=week_ago, is_new_ip=True).count(),
    })

@login_required
@analyst_required
def export_csv(request, model):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="its_{model}_export.csv"'
    writer = csv.writer(response)
    if model == 'login_logs':
        writer.writerow(['ID','Timestamp','Username','IP Address','Status','Action','Attempts'])
        for r in LoginAttempt.objects.all()[:1000]:
            writer.writerow([r.id, timezone.localtime(r.timestamp).strftime('%Y-%m-%d %H:%M:%S'), r.username, r.ip_address, r.status, r.action, r.attempts_from_ip])
    elif model == 'blacklist':
        writer.writerow(['IP Address','Reason','Failed Attempts','Blocked At','Expires','Source'])
        for r in BlacklistedIP.objects.all():
            writer.writerow([r.ip_address, r.reason, r.failed_attempts, r.blocked_at, r.expires_display, r.source])
    elif model == 'events':
        writer.writerow(['Timestamp','Event Type','IP Address','Details','Severity','Response'])
        for r in SecurityEvent.objects.all()[:1000]:
            writer.writerow([timezone.localtime(r.timestamp).strftime('%Y-%m-%d %H:%M:%S'), r.event_type, r.ip_address, r.details, r.severity, r.response])
    elif model == 'audit':
        writer.writerow(['Timestamp','Level','Module','Message','Performed By'])
        for r in AuditLog.objects.all()[:1000]:
            writer.writerow([timezone.localtime(r.timestamp).strftime('%Y-%m-%d %H:%M:%S'), r.level, r.module, r.message, r.performed_by or ''])
    return response

@login_required
@analyst_required
def export_pdf(request):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import cm

    buf    = io.BytesIO()
    doc    = SimpleDocTemplate(buf, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []
    now    = timezone.now()
    week_ago = now - timedelta(days=7)

    story.append(Paragraph("IntrusionTolerant System — Security Report", styles['Title']))
    story.append(Paragraph(f"Generated: {timezone.localtime(now).strftime('%Y-%m-%d %H:%M WAT')}", styles['Normal']))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph("Weekly Summary", styles['Heading2']))

    summary = [
        ['Metric','Value'],
        ['Total Login Attempts (7d)', str(LoginAttempt.objects.filter(timestamp__gte=week_ago).count())],
        ['Failed Login Attempts',     str(LoginAttempt.objects.filter(timestamp__gte=week_ago, status='FAILED').count())],
        ['IPs Blacklisted (total)',   str(BlacklistedIP.objects.count())],
        ['Security Events (7d)',      str(SecurityEvent.objects.filter(timestamp__gte=week_ago).count())],
        ['Critical Events (7d)',      str(SecurityEvent.objects.filter(timestamp__gte=week_ago, severity='CRITICAL').count())],
        ['Active Users',              str(UserProfile.objects.filter(status='ACTIVE').count())],
        ['New IP Login Alerts (7d)',  str(LoginAttempt.objects.filter(timestamp__gte=week_ago, is_new_ip=True).count())],
    ]
    t = Table(summary, colWidths=[10*cm, 6*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0), colors.HexColor('#1F3A8C')),
        ('TEXTCOLOR',(0,0),(-1,0), colors.white),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.HexColor('#EEF2FF'),colors.white]),
        ('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#CCCCCC')),
        ('PADDING',(0,0),(-1,-1),6),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Recent Security Events", styles['Heading2']))
    ev_data = [['Time','Event Type','IP Address','Severity','Response']]
    for e in SecurityEvent.objects.all()[:15]:
        ev_data.append([timezone.localtime(e.timestamp).strftime('%Y-%m-%d %H:%M'), e.event_type, e.ip_address, e.severity, e.response])
    t2 = Table(ev_data, colWidths=[3.5*cm,4*cm,3.5*cm,2.5*cm,3*cm])
    t2.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#1F3A8C')),
        ('TEXTCOLOR',(0,0),(-1,0),colors.white),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),
        ('FONTSIZE',(0,0),(-1,-1),8),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.HexColor('#FFF5F5'),colors.white]),
        ('GRID',(0,0),(-1,-1),0.5,colors.HexColor('#CCCCCC')),
        ('PADDING',(0,0),(-1,-1),4),
    ]))
    story.append(t2)
    doc.build(story)
    buf.seek(0)
    response = HttpResponse(buf, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="its_report_{now.strftime("%Y%m%d")}.pdf"'
    audit('INFO','RPT', f'PDF report generated by {request.user.username}.', request.user)
    return response
