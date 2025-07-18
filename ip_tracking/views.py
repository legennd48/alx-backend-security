from django.shortcuts import render
from django.http import HttpResponse, HttpResponseForbidden
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
import json

@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@ratelimit(key='user', rate='10/m', method='POST', block=True)
@require_http_methods(["GET", "POST"])
def custom_login(request):
    """
    Custom login view with rate limiting:
    - Anonymous users: 5 requests per minute
    - Authenticated users: 10 requests per minute
    """
    if request.method == 'GET':
        return render(request, 'ip_tracking/login.html')
    
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if username and password:
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return HttpResponse("Login successful!")
            else:
                return HttpResponse("Invalid credentials!", status=401)
        
        return HttpResponse("Username and password required!", status=400)

@ratelimit(key='ip', rate='10/m', method='GET', block=True)
def sensitive_data(request):
    """
    A sensitive view that shows user data with rate limiting
    """
    return HttpResponse("This is sensitive data that requires rate limiting.")

@ratelimit(key='ip', rate='3/m', method='POST', block=True)
@csrf_exempt
def api_endpoint(request):
    """
    API endpoint with strict rate limiting
    """
    if request.method == 'POST':
        return HttpResponse(json.dumps({"message": "API call successful"}), 
                          content_type="application/json")
    return HttpResponse("Method not allowed", status=405)

def ratelimited(request, exception):
    """
    Custom view for when rate limits are exceeded
    """
    return HttpResponseForbidden(
        "Rate limit exceeded. Please try again later."
    )

def home(request):
    """
    Simple home view without rate limiting
    """
    return HttpResponse("""
    <h1>IP Tracking Demo</h1>
    <p><a href="/login/">Login (Rate Limited)</a></p>
    <p><a href="/sensitive/">Sensitive Data (Rate Limited)</a></p>
    <p><a href="/api/">API Endpoint (Rate Limited)</a></p>
    """)
