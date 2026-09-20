#!/usr/bin/env bash
set -o errexit

pip install -r requirements.txt
python manage.py collectstatic --no-input
python manage.py migrate

python manage.py shell << 'PYEOF'
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
from dashboard.models import SystemSetting, AuditLog, LoginAttempt, SecurityEvent, BlacklistedIP

# Create admin user
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@its-cloud.local', 'admin12345')
    print('Admin created: admin / admin12345')

# Default settings
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
}.items():
    SystemSetting.set(k, v)

# Seed 7 days of login attempt data for the chart
now = timezone.now()
if LoginAttempt.objects.count() == 0:
    demo = [
        (6, [('admin','197.210.85.14','SUCCESS','ALLOWED',1)]*78  + [('root','185.220.101.42','FAILED','FLAGGED',2)]*22),
        (5, [('admin','197.210.85.14','SUCCESS','ALLOWED',1)]*102 + [('admin','91.108.4.167','FAILED','FLAGGED',3)]*38),
        (4, [('admin','197.210.85.14','SUCCESS','ALLOWED',1)]*65  + [('test','103.21.244.0','FAILED','MONITORED',1)]*18),
        (3, [('admin','197.210.85.14','SUCCESS','ALLOWED',1)]*134 + [('root','45.155.205.233','FAILED','FLAGGED',4)]*52),
        (2, [('admin','197.210.85.14','SUCCESS','ALLOWED',1)]*88  + [('admin','185.220.101.42','FAILED','BLACKLISTED',12)]*96),
        (1, [('admin','197.210.85.14','SUCCESS','ALLOWED',1)]*110 + [('user','78.46.82.200','FAILED','FLAGGED',5)]*44),
        (0, [('admin','197.210.85.14','SUCCESS','ALLOWED',1)]*120 + [('root','91.108.4.167','FAILED','FLAGGED',3)]*57),
    ]
    bulk = []
    for days_ago, attempts in demo:
        base_time = now - timedelta(days=days_ago, hours=12)
        for i, (user, ip, status, action, count) in enumerate(attempts[:20]):
            bulk.append(LoginAttempt(
                username=user, ip_address=ip, status=status,
                action=action, attempts_from_ip=count,
                timestamp=base_time + timedelta(minutes=i*5)
            ))
    LoginAttempt.objects.bulk_create(bulk)
    print(f'Seeded {len(bulk)} login attempt records')

# Seed security events
if SecurityEvent.objects.count() == 0:
    events = [
        ('Brute Force','185.220.101.42','12 failed attempts in 45 seconds','CRITICAL','Auto-Blacklisted', 2),
        ('Credential Stuffing','91.108.4.167','3 different usernames attempted with same password','WARNING','Flagged', 5),
        ('Rate Limit Exceeded','103.21.244.0','38 req/min (limit: 30)','WARNING','Throttled', 10),
        ('Brute Force','45.155.205.233','8 failed attempts in 2 minutes','CRITICAL','Auto-Blacklisted', 15),
        ('Scan Detected','194.165.16.78','47 paths probed in 15 seconds','CRITICAL','Blocked', 20),
        ('Failed Login','154.113.52.77','2 consecutive failed login attempts','INFO','Monitored', 30),
    ]
    for etype, ip, details, sev, resp, mins in events:
        SecurityEvent.objects.create(
            event_type=etype, ip_address=ip, details=details,
            severity=sev, response=resp,
            timestamp=now - timedelta(minutes=mins)
        )
    print('Seeded security events')

# Seed blacklisted IPs
if BlacklistedIP.objects.count() == 0:
    blist = [
        ('185.220.101.42','BRUTE_FORCE',12,'AUTO',False, now - timedelta(hours=2)),
        ('45.155.205.233','BRUTE_FORCE',8,'AUTO',False, now - timedelta(hours=3)),
        ('78.46.82.200','BRUTE_FORCE',15,'AUTO',True, now - timedelta(days=1)),
        ('194.165.16.78','SCANNER',0,'MANUAL',True, now - timedelta(days=2)),
        ('5.188.62.140','MANUAL',0,'MANUAL',True, now - timedelta(days=3)),
    ]
    for ip, reason, attempts, src, permanent, blocked_at in blist:
        BlacklistedIP.objects.create(
            ip_address=ip, reason=reason, failed_attempts=attempts,
            source=src, is_permanent=permanent,
            blocked_at=blocked_at,
            expires_at=None if permanent else blocked_at + timedelta(hours=24)
        )
    print('Seeded blacklisted IPs')

# Seed audit logs
if AuditLog.objects.count() == 0:
    logs = [
        ('CRIT','AUTH','[AUTH] Brute force detected: 185.220.101.42 — 12 failures in 45s. Auto-blacklist applied.', 2),
        ('WARN','AUTH','[AUTH] Failed login: user=root ip=91.108.4.167 attempt=5. Threshold approaching.', 5),
        ('OK','AUTH','[AUTH] Successful login: user=admin ip=197.210.85.14 session=sess_a3f7c2.', 8),
        ('WARN','RATE','[RATE] Rate limit triggered: ip=103.21.244.0 req_rate=38/min limit=30/min.', 10),
        ('CRIT','AUTH','[AUTH] Brute force detected: 45.155.205.233 — 8 failures in 2min. Auto-blacklist applied.', 15),
        ('INFO','AUTH','[AUTH] Failed login: user=admin ip=154.113.52.77 attempt=2. Monitoring.', 30),
        ('CRIT','SEC','[SEC] Port scan detected: ip=194.165.16.78 paths_probed=47. IP blocked.', 45),
        ('INFO','SYS','[SYS] Proactive recovery initiated: replica-4 suspended for reinit. BFT consensus maintained.', 60),
        ('OK','SYS','[SYS] Replica-4 restored from verified snapshot. State sync complete. Rejoined consensus cluster.', 75),
        ('OK','SYS','[SYS] Scheduled audit log integrity check passed. 0 tampering events detected.', 90),
        ('OK','SYS','[SYS] System initialised. All components active. BFT consensus layer ready.', 120),
    ]
    for level, module, message, mins in logs:
        AuditLog.objects.create(level=level, module=module, message=message, timestamp=now - timedelta(minutes=mins))
    print('Seeded audit logs')

print('All setup complete.')
PYEOF
