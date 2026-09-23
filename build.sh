#!/usr/bin/env bash
set -o errexit

pip install -r requirements.txt --break-system-packages 2>/dev/null || pip install -r requirements.txt
python manage.py collectstatic --no-input
python manage.py migrate

python manage.py shell << 'PYEOF'
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from dashboard.models import (SystemSetting, AuditLog, LoginAttempt,
                               SecurityEvent, BlacklistedIP, UserProfile, UserSession)

now = timezone.now()

# ── ADMIN USER ────────────────────────────────────────────────────
if not User.objects.filter(username='admin').exists():
    u = User.objects.create_superuser('admin', 'admin@its-cloud.local', 'admin12345')
    u.first_name = 'System'; u.last_name = 'Administrator'; u.save()
    UserProfile.objects.create(user=u, role='ADMIN', status='ACTIVE',
        department='IT Security', known_ips='127.0.0.1')
    print('Admin created: admin / admin12345')
else:
    admin = User.objects.get(username='admin')
    if not UserProfile.objects.filter(user=admin).exists():
        UserProfile.objects.create(user=admin, role='ADMIN', status='ACTIVE',
            department='IT Security', known_ips='127.0.0.1')

# ── DEFAULT SETTINGS ──────────────────────────────────────────────
for k, v in {
    'max_failed_attempts': '5',
    'detection_window_seconds': '300',
    'blacklist_duration_hours': '24',
    'rate_limit_rpm': '30',
    'burst_allowance': '10',
    'alert_email': 'admin@its-cloud.local',
    'log_retention_days': '90',
    'brute_force_enabled': 'true',
    'rate_limit_enabled': 'true',
    'email_critical': 'true',
    'email_warning': 'true',
    'audit_enabled': 'true',
    'log_all_logins': 'true',
    'require_approval': 'true',
}.items():
    SystemSetting.set(k, v)

admin = User.objects.get(username='admin')

# ── LOGIN ATTEMPTS (chart data — 7 days) ─────────────────────────
if LoginAttempt.objects.count() == 0:
    demo = [(6,78,22),(5,102,38),(4,65,18),(3,134,52),(2,88,96),(1,110,44),(0,120,57)]
    bulk = []
    for days_ago, ok_count, fail_count in demo:
        base = now - timedelta(days=days_ago, hours=10)
        for i in range(min(ok_count, 15)):
            bulk.append(LoginAttempt(
                username='admin', ip_address='197.210.85.14',
                status='SUCCESS', action='ALLOWED', user=admin,
                timestamp=base + timedelta(minutes=i*8)
            ))
        for i in range(min(fail_count, 10)):
            bulk.append(LoginAttempt(
                username='root', ip_address=f'185.{i}.101.42',
                status='FAILED', action='FLAGGED', attempts_from_ip=i+1,
                timestamp=base + timedelta(minutes=i*12+5)
            ))
    LoginAttempt.objects.bulk_create(bulk)
    print(f'Seeded {len(bulk)} login records')

# ── SECURITY EVENTS ───────────────────────────────────────────────
if SecurityEvent.objects.count() == 0:
    for etype, ip, details, sev, resp, mins in [
        ('Brute Force','185.220.101.42','12 failed attempts in 45s','CRITICAL','Auto-Blacklisted',2),
        ('Credential Stuffing','91.108.4.167','3 usernames tried with same password','WARNING','Flagged',5),
        ('Rate Limit Exceeded','103.21.244.0','38 req/min (limit: 30)','WARNING','Throttled',10),
        ('Brute Force','45.155.205.233','8 failures in 2 minutes','CRITICAL','Auto-Blacklisted',15),
        ('Scan Detected','194.165.16.78','47 paths probed in 15 seconds','CRITICAL','Blocked',25),
        ('New IP Login','197.210.85.14','Admin logged in from new IP address','WARNING','Flagged',40),
        ('New Registration','10.0.0.5','User analyst1 registered — pending approval','INFO','Awaiting Approval',60),
    ]:
        SecurityEvent.objects.create(event_type=etype, ip_address=ip,
            details=details, severity=sev, response=resp,
            timestamp=now - timedelta(minutes=mins))
    print('Seeded security events')

# ── BLACKLISTED IPs ───────────────────────────────────────────────
if BlacklistedIP.objects.count() == 0:
    for ip, reason, attempts, src, perm in [
        ('185.220.101.42','BRUTE_FORCE',12,'AUTO',False),
        ('45.155.205.233','BRUTE_FORCE',8,'AUTO',False),
        ('78.46.82.200','BRUTE_FORCE',15,'AUTO',True),
        ('194.165.16.78','SCANNER',0,'MANUAL',True),
        ('5.188.62.140','MANUAL',0,'MANUAL',True),
    ]:
        BlacklistedIP.objects.create(
            ip_address=ip, reason=reason, failed_attempts=attempts,
            source=src, is_permanent=perm,
            blocked_at=now - timedelta(hours=2),
            expires_at=None if perm else now + timedelta(hours=22)
        )
    print('Seeded blacklisted IPs')

# ── AUDIT LOGS ────────────────────────────────────────────────────
if AuditLog.objects.count() == 0:
    for level, module, msg, mins in [
        ('CRIT','AUTH','[AUTH] Brute force detected: 185.220.101.42 — 12 failures in 45s. Auto-blacklisted.',2),
        ('WARN','AUTH','[AUTH] Failed login: user=root ip=91.108.4.167 attempt=5. Threshold approaching.',5),
        ('OK','AUTH','[AUTH] Successful login: user=admin ip=197.210.85.14 session=sess_a3f7c2.',8),
        ('WARN','RATE','[RATE] Rate limit triggered: ip=103.21.244.0 req_rate=38/min limit=30/min.',10),
        ('CRIT','SEC','[SEC] Port scan detected: ip=194.165.16.78 paths_probed=47. IP blocked.',25),
        ('INFO','SYS','[SYS] Proactive recovery initiated: replica-4 suspended. BFT consensus maintained (3 replicas).',30),
        ('OK','SYS','[SYS] Replica-4 restored from verified snapshot. State sync complete. Rejoined consensus.',45),
        ('OK','SYS','[SYS] Scheduled audit log integrity check passed. 0 tampering events. Signature valid.',60),
        ('OK','SYS','[SYS] System initialised. All components active. BFT consensus layer ready.',120),
    ]:
        AuditLog.objects.create(level=level, module=module, message=msg,
            performed_by=admin, timestamp=now - timedelta(minutes=mins))
    print('Seeded audit logs')

# ── DEMO PENDING USER ─────────────────────────────────────────────
if not User.objects.filter(username='analyst1').exists():
    u2 = User.objects.create_user(
        'analyst1', 'analyst1@company.com', 'Pass1234!',
        first_name='Sarah', last_name='Analyst', is_active=False
    )
    UserProfile.objects.create(user=u2, role='VIEWER', status='PENDING',
        department='Security Operations', known_ips='10.0.0.5')
    print('Demo pending user created: analyst1 (awaiting admin approval)')

print('All setup complete.')
PYEOF
