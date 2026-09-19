from django.contrib import admin
from .models import LoginAttempt, BlacklistedIP, SecurityEvent, AuditLog, SystemSetting

@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ['username', 'ip_address', 'status', 'action', 'attempts_from_ip', 'timestamp']
    list_filter = ['status', 'action']
    search_fields = ['username', 'ip_address']

@admin.register(BlacklistedIP)
class BlacklistedIPAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'reason', 'source', 'failed_attempts', 'blocked_at', 'is_permanent']
    list_filter = ['source', 'reason', 'is_permanent']

@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ['event_type', 'ip_address', 'severity', 'response', 'timestamp']
    list_filter = ['severity', 'event_type']

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['level', 'module', 'message', 'timestamp']
    list_filter = ['level', 'module']

@admin.register(SystemSetting)
class SystemSettingAdmin(admin.ModelAdmin):
    list_display = ['key', 'value', 'updated_at']
