from ipware import get_client_ip
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP

class LogIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip, _ = get_client_ip(request)
        path = request.path
        if ip:
            # Block if IP is blacklisted
            if BlockedIP.objects.filter(ip_address=ip).exists():
                return HttpResponseForbidden("Your IP is blocked.")
            RequestLog.objects.create(ip_address=ip, path=path)
        response = self.get_response(request)
        return response
