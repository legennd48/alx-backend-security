import os
import requests
from dotenv import load_dotenv
from ipware import get_client_ip
from django.http import HttpResponseForbidden
from django.core.cache import cache
from .models import RequestLog, BlockedIP

load_dotenv()
API_KEY = os.getenv('IPGEOLOCATION_API_KEY')

def get_geolocation(ip, api_key):
    """Get geolocation data for an IP address using ipgeolocation.io API"""
    try:
        url = f"https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={ip}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'country': data.get('country_name', ''),
                'city': data.get('city', ''),
            }
    except Exception as e:
        # Log the error if needed, but don't break the middleware
        pass
    return {'country': '', 'city': ''}

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
                geo_data = get_geolocation(ip, API_KEY)
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
