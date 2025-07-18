from ipware import get_client_ip
from .models import RequestLog

class LogIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip, _ = get_client_ip(request)
        path = request.path
        # Save log only if IP is found
        if ip:
            RequestLog.objects.create(ip_address=ip, path=path)
        response = self.get_response(request)
        return response
