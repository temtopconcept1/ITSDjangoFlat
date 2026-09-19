from django.contrib import admin
from django.urls import path, include
from dashboard import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index_redirect),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('login-logs/', views.login_logs, name='login_logs'),
    path('blacklist/', views.blacklist, name='blacklist'),
    path('blacklist/add/', views.blacklist_add, name='blacklist_add'),
    path('blacklist/remove/<int:pk>/', views.blacklist_remove, name='blacklist_remove'),
    path('events/', views.events, name='events'),
    path('rate-limits/', views.rate_limits, name='rate_limits'),
    path('rate-limits/save/', views.rate_limits_save, name='rate_limits_save'),
    path('audit/', views.audit_logs, name='audit_logs'),
    path('settings/', views.settings_view, name='settings'),
    path('settings/save/', views.settings_save, name='settings_save'),
    path('api/stats/', views.api_stats, name='api_stats'),
]
