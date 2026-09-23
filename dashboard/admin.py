from django.contrib import admin
from .models import LoginAttempt, BlacklistedIP, SecurityEvent, AuditLog, SystemSetting, UserProfile, UserSession

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user','role','status','department','registered_at','last_seen']
    list_filter  = ['role','status']
    search_fields= ['user__username','user__email','department']

@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    list_display = ['user','ip_address','is_new_ip','is_active','created_at']
    list_filter  = ['is_active','is_new_ip']

@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ['username','ip_address','status','action','is_new_ip','attempts_from_ip','timestamp']
    list_filter  = ['status','action','is_new_ip']
    search_fields= ['username','ip_address']

@admin.register(BlacklistedIP)
class BlacklistedIPAdmin(admin.ModelAdmin):
    list_display = ['ip_address','reason','source','failed_attempts','blocked_at','is_permanent']
    list_filter  = ['source','reason','is_permanent']

@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ['event_type','ip_address','severity','response','timestamp']
    list_filter  = ['severity','event_type']

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['level','module','message','performed_by','timestamp']
    list_filter  = ['level','module']

@admin.register(SystemSetting)
class SystemSettingAdmin(admin.ModelAdmin):
    list_display = ['key','value','updated_at']
