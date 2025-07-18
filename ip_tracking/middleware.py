from ipware import get_client_ip
from django.http import HttpResponseForbidden
from django.core.cache import cache
from ipgeolocation import IpGeolocationAPI
from .models import RequestLog, BlockedIP

# Replace with your actual API key if needed
API_KEY = 'YOUR_API_KEY'
geo = IpGeolocationAPI(API_KEY)

class LogIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip, _ = get_client_ip(request)
        path = request.path
        country = ''
        city = ''
        if ip:
            # Block if IP is blacklisted
            if BlockedIP.objects.filter(ip_address=ip).exists():
                return HttpResponseForbidden("Your IP is blocked.")

            # Try to get geolocation from cache
            cache_key = f"geo_{ip}"
            geo_data = cache.get(cache_key)
            if not geo_data:
                response = geo.get_geolocation(ip_address=ip)
                geo_data = {
                    'country': response.get('country_name', ''),
                    'city': response.get('city', ''),
                }
                cache.set(cache_key, geo_data, 60 * 60 * 24)  # Cache for 24 hours
            country = geo_data['country']
            city = geo_data['city']

            RequestLog.objects.create(
                ip_address=ip,
                path=path,
                country=country,
                city=city
            )
        response = self.get_response(request)
        return response
