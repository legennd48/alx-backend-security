from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.custom_login, name='custom_login'),
    path('sensitive/', views.sensitive_data, name='sensitive_data'),
    path('api/', views.api_endpoint, name='api_endpoint'),
]
