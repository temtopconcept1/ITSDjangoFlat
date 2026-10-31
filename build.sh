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

# ── INIT LOG (no fake activity: the dashboard shows only real events) ──
if AuditLog.objects.count() == 0:
    AuditLog.objects.create(level='OK', module='SYS', performed_by=admin,
        message='[SYS] System initialised. All components active.')

print('All setup complete.')
PYEOF
