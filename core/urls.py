from django.urls import path

from core import views


urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('api/health', views.health, name='health'),
    path('api/dashboard', views.dashboard_data, name='dashboard_data'),
    path('setup', views.setup, name='setup'),
    path('login', views.login_view, name='login'),
    path('logout', views.logout_view, name='logout'),
    path('account', views.account, name='account'),
    path('users', views.users, name='users'),
    path('users/<int:user_id>/toggle', views.toggle_user, name='toggle_user'),
    path('users/<int:user_id>/reset-password', views.reset_user_password, name='reset_user_password'),
    path('settings', views.settings_view, name='settings'),
    path('wake_device', views.wake_device, name='wake_device'),
    path('add_device', views.add_device, name='add_device'),
    path('edit_device/<int:index>', views.edit_device, name='edit_device'),
    path('remove_device', views.remove_device, name='remove_device'),
    path('discover', views.discover, name='discover'),
    path('discover/scan', views.scan_network, name='scan_network'),
    path('add_selected_devices', views.add_selected_devices, name='add_selected_devices'),
    path('device_status/<str:ip>', views.device_status, name='device_status'),
    path('discover_mac', views.discover_mac, name='discover_mac'),
    path('api/ups', views.add_ups, name='add_ups'),
    path('api/ups/test', views.test_ups, name='test_ups'),
    path('api/ups/status', views.ups_status, name='ups_status'),
    path('api/ups/<str:ups_id>', views.update_ups, name='update_ups'),
]
