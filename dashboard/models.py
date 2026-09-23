from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta


# ── USER PROFILE ──────────────────────────────────────────────────
class UserProfile(models.Model):
    ROLE_CHOICES = [
        ('ADMIN',    'Administrator'),
        ('ANALYST',  'Security Analyst'),
        ('VIEWER',   'Viewer'),
    ]
    STATUS_CHOICES = [
        ('PENDING',   'Pending Approval'),
        ('ACTIVE',    'Active'),
        ('SUSPENDED', 'Suspended'),
        ('REJECTED',  'Rejected'),
    ]
    user          = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    role          = models.CharField(max_length=10, choices=ROLE_CHOICES, default='VIEWER')
    status        = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    phone         = models.CharField(max_length=20, blank=True)
    department    = models.CharField(max_length=100, blank=True)
    bio           = models.TextField(blank=True)
    avatar_initials = models.CharField(max_length=2, blank=True)
    registered_at = models.DateTimeField(default=timezone.now)
    approved_at   = models.DateTimeField(null=True, blank=True)
    approved_by   = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='approvals')
    last_seen     = models.DateTimeField(null=True, blank=True)
    known_ips     = models.TextField(blank=True, help_text="Comma-separated list of known IPs")

    class Meta:
        ordering = ['-registered_at']

    def __str__(self):
        return f"{self.user.username} ({self.role})"

    def get_known_ips(self):
        return [ip.strip() for ip in self.known_ips.split(',') if ip.strip()]

    def add_known_ip(self, ip):
        ips = self.get_known_ips()
        if ip not in ips:
            ips.append(ip)
            self.known_ips = ','.join(ips)
            self.save()
            return True  # new IP
        return False  # already known

    @property
    def is_active_user(self):
        return self.status == 'ACTIVE'

    @property
    def initials(self):
        fn = self.user.first_name
        ln = self.user.last_name
        if fn and ln:
            return (fn[0] + ln[0]).upper()
        return self.user.username[:2].upper()


# ── USER SESSION ──────────────────────────────────────────────────
class UserSession(models.Model):
    user          = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sessions')
    session_key   = models.CharField(max_length=40, unique=True)
    ip_address    = models.GenericIPAddressField()
    user_agent    = models.TextField(blank=True)
    country       = models.CharField(max_length=60, blank=True)
    is_new_ip     = models.BooleanField(default=False)
    created_at    = models.DateTimeField(default=timezone.now)
    last_activity = models.DateTimeField(default=timezone.now)
    is_active     = models.BooleanField(default=True)

    class Meta:
        ordering = ['-last_activity']

    def __str__(self):
        return f"{self.user.username} @ {self.ip_address}"

    @property
    def duration(self):
        delta = timezone.now() - self.created_at
        h = int(delta.total_seconds() // 3600)
        m = int((delta.total_seconds() % 3600) // 60)
        if h > 0:
            return f"{h}h {m}m"
        return f"{m}m"


# ── LOGIN ATTEMPT ─────────────────────────────────────────────────
class LoginAttempt(models.Model):
    STATUS_CHOICES = [('SUCCESS','Success'),('FAILED','Failed')]
    ACTION_CHOICES = [
        ('ALLOWED',      'Allowed'),
        ('BLACKLISTED',  'IP Blacklisted'),
        ('RATE_LIMITED', 'Rate Limited'),
        ('FLAGGED',      'Flagged'),
        ('MONITORED',    'Monitored'),
        ('NEW_IP',       'New IP Alert'),
        ('PENDING',      'Account Pending'),
        ('SUSPENDED',    'Account Suspended'),
    ]
    user              = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    username          = models.CharField(max_length=150)
    ip_address        = models.GenericIPAddressField()
    status            = models.CharField(max_length=10, choices=STATUS_CHOICES)
    action            = models.CharField(max_length=20, choices=ACTION_CHOICES, default='MONITORED')
    attempts_from_ip  = models.IntegerField(default=1)
    timestamp         = models.DateTimeField(default=timezone.now)
    user_agent        = models.TextField(blank=True)
    is_new_ip         = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.username} from {self.ip_address} — {self.status}"


# ── BLACKLISTED IP ────────────────────────────────────────────────
class BlacklistedIP(models.Model):
    SOURCE_CHOICES = [('AUTO','Automatic'),('MANUAL','Manual')]
    REASON_CHOICES = [
        ('BRUTE_FORCE',   'Brute force attack'),
        ('RATE_LIMIT',    'Rate limit violation'),
        ('CRED_STUFFING', 'Credential stuffing'),
        ('MANUAL',        'Manual block'),
        ('SCANNER',       'Known scanner'),
        ('NEW_IP_ABUSE',  'New IP abuse'),
    ]
    ip_address      = models.GenericIPAddressField(unique=True)
    reason          = models.CharField(max_length=20, choices=REASON_CHOICES)
    failed_attempts = models.IntegerField(default=0)
    source          = models.CharField(max_length=10, choices=SOURCE_CHOICES, default='AUTO')
    blocked_at      = models.DateTimeField(default=timezone.now)
    expires_at      = models.DateTimeField(null=True, blank=True)
    is_permanent    = models.BooleanField(default=False)
    notes           = models.TextField(blank=True)
    added_by        = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ['-blocked_at']

    def __str__(self):
        return f"{self.ip_address} ({self.reason})"

    @property
    def is_active(self):
        if self.is_permanent:
            return True
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        return True

    @property
    def expires_display(self):
        if self.is_permanent:
            return 'Permanent'
        if self.expires_at:
            diff = self.expires_at - timezone.now()
            if diff.total_seconds() < 0:
                return 'Expired'
            hours = int(diff.total_seconds() // 3600)
            mins  = int((diff.total_seconds() % 3600) // 60)
            if hours >= 24:
                return f"{hours//24}d"
            if hours > 0:
                return f"{hours}h {mins}m"
            return f"{mins}m"
        return 'Unknown'


# ── SECURITY EVENT ────────────────────────────────────────────────
class SecurityEvent(models.Model):
    SEV_CHOICES = [('CRITICAL','Critical'),('WARNING','Warning'),('INFO','Info')]
    event_type  = models.CharField(max_length=50)
    ip_address  = models.GenericIPAddressField()
    details     = models.TextField()
    severity    = models.CharField(max_length=10, choices=SEV_CHOICES)
    response    = models.CharField(max_length=100)
    user        = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    timestamp   = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.event_type} from {self.ip_address}"


# ── AUDIT LOG ─────────────────────────────────────────────────────
class AuditLog(models.Model):
    LEVEL_CHOICES = [('CRIT','Critical'),('WARN','Warning'),('INFO','Info'),('OK','OK')]
    level       = models.CharField(max_length=4, choices=LEVEL_CHOICES)
    module      = models.CharField(max_length=10)
    message     = models.TextField()
    timestamp   = models.DateTimeField(default=timezone.now)
    performed_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.level}] {self.message[:60]}"


# ── SYSTEM SETTING ────────────────────────────────────────────────
class SystemSetting(models.Model):
    key        = models.CharField(max_length=100, unique=True)
    value      = models.TextField()
    updated_at = models.DateTimeField(auto_now=True)

    @classmethod
    def get(cls, key, default=''):
        try:
            return cls.objects.get(key=key).value
        except cls.DoesNotExist:
            return default

    @classmethod
    def set(cls, key, value):
        obj, _ = cls.objects.get_or_create(key=key)
        obj.value = str(value)
        obj.save()

    def __str__(self):
        return f"{self.key} = {self.value}"
