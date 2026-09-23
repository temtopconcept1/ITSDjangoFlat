from django.contrib import admin
from django.urls import path
from dashboard import views

urlpatterns = [
    path('admin/',               admin.site.urls),
    path('',                     views.index_redirect),
    # Auth
    path('login/',               views.login_view,        name='login'),
    path('logout/',              views.logout_view,       name='logout'),
    path('register/',            views.register_view,     name='register'),
    # Dashboard pages
    path('dashboard/',           views.dashboard,         name='dashboard'),
    path('login-logs/',          views.login_logs,        name='login_logs'),
    path('blacklist/',           views.blacklist,         name='blacklist'),
    path('blacklist/add/',       views.blacklist_add,     name='blacklist_add'),
    path('blacklist/remove/<int:pk>/', views.blacklist_remove, name='blacklist_remove'),
    path('events/',              views.events,            name='events'),
    path('rate-limits/',         views.rate_limits,       name='rate_limits'),
    path('rate-limits/save/',    views.rate_limits_save,  name='rate_limits_save'),
    path('audit/',               views.audit_logs,        name='audit_logs'),
    path('settings/',            views.settings_view,     name='settings'),
    path('settings/save/',       views.settings_save,     name='settings_save'),
    # User management
    path('users/',               views.user_list,         name='user_list'),
    path('users/<int:pk>/approve/',  views.user_approve,  name='user_approve'),
    path('users/<int:pk>/reject/',   views.user_reject,   name='user_reject'),
    path('users/<int:pk>/suspend/',  views.user_suspend,  name='user_suspend'),
    path('users/<int:pk>/activate/', views.user_activate, name='user_activate'),
    path('users/<int:pk>/delete/',   views.user_delete,   name='user_delete'),
    path('users/<int:pk>/role/',     views.user_role,     name='user_role'),
    # Sessions
    path('sessions/',            views.sessions_view,     name='sessions'),
    path('sessions/<int:pk>/kill/', views.session_kill,  name='session_kill'),
    # Profile
    path('profile/',             views.profile_view,      name='profile'),
    path('profile/save/',        views.profile_save,      name='profile_save'),
    path('profile/password/',    views.change_password,   name='change_password'),
    # Reports
    path('reports/',             views.reports_view,      name='reports'),
    path('reports/pdf/',         views.export_pdf,        name='export_pdf'),
    path('reports/csv/<str:model>/', views.export_csv,   name='export_csv'),
    # API
    path('api/stats/',           views.api_stats,         name='api_stats'),
    path('api/chart/',           views.api_chart,         name='api_chart'),
]
