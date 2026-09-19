#!/usr/bin/env bash
set -o errexit
pip install -r requirements.txt
python manage.py collectstatic --no-input
python manage.py migrate
python manage.py shell << 'PYEOF'
from django.contrib.auth.models import User
from dashboard.models import SystemSetting, AuditLog
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@its-cloud.local', 'admin12345')
    print('Admin created: admin / admin12345')
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
AuditLog.objects.create(level='OK', module='SYS', message='[SYS] System initialised. BFT consensus layer ready.')
print('Setup complete.')
PYEOF
