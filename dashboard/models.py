from django.db import models
from django.utils import timezone


class LoginAttempt(models.Model):
    STATUS_CHOICES = [('SUCCESS', 'Success'), ('FAILED', 'Failed')]
    ACTION_CHOICES = [
        ('ALLOWED', 'Allowed'),
        ('BLACKLISTED', 'IP Blacklisted'),
        ('RATE_LIMITED', 'Rate Limited'),
        ('FLAGGED', 'Flagged'),
        ('MONITORED', 'Monitored'),
    ]
    username = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES, default='MONITORED')
    attempts_from_ip = models.IntegerField(default=1)
    timestamp = models.DateTimeField(default=timezone.now)
    user_agent = models.TextField(blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.username} from {self.ip_address} at {self.timestamp}"


class BlacklistedIP(models.Model):
    SOURCE_CHOICES = [('AUTO', 'Automatic'), ('MANUAL', 'Manual')]
    REASON_CHOICES = [
        ('BRUTE_FORCE', 'Brute force attack'),
        ('RATE_LIMIT', 'Rate limit violation'),
        ('CRED_STUFFING', 'Credential stuffing'),
        ('MANUAL', 'Manual block'),
        ('SCANNER', 'Known scanner'),
    ]
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=20, choices=REASON_CHOICES)
    failed_attempts = models.IntegerField(default=0)
    source = models.CharField(max_length=10, choices=SOURCE_CHOICES, default='AUTO')
    blocked_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_permanent = models.BooleanField(default=False)
    notes = models.TextField(blank=True)

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
            mins = int((diff.total_seconds() % 3600) // 60)
            if hours >= 24:
                return f"{hours // 24} day(s)"
            if hours > 0:
                return f"{hours}h {mins}m"
            return f"{mins}m"
        return 'Unknown'


class SecurityEvent(models.Model):
    SEV_CHOICES = [('CRITICAL', 'Critical'), ('WARNING', 'Warning'), ('INFO', 'Info')]
    event_type = models.CharField(max_length=50)
    ip_address = models.GenericIPAddressField()
    details = models.TextField()
    severity = models.CharField(max_length=10, choices=SEV_CHOICES)
    response = models.CharField(max_length=100)
    timestamp = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.event_type} from {self.ip_address}"


class AuditLog(models.Model):
    LEVEL_CHOICES = [('CRIT','Critical'),('WARN','Warning'),('INFO','Info'),('OK','OK')]
    level = models.CharField(max_length=4, choices=LEVEL_CHOICES)
    module = models.CharField(max_length=10)
    message = models.TextField()
    timestamp = models.DateTimeField(default=timezone.now)
    hash_chain = models.CharField(max_length=64, blank=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.level}] {self.message[:60]}"


class SystemSetting(models.Model):
    key = models.CharField(max_length=100, unique=True)
    value = models.TextField()
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
