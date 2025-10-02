import logging
from django.contrib import auth
from django.conf import settings

logger = logging.getLogger(__name__)


class IAPAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not getattr(settings, "IAP_ENABLED", False):
            return self.get_response(request)

        # Bypass for exempt URLs
        iap_exempt_urls = getattr(settings, "IAP_EXEMPT_URLS", [])
        if any(request.path.startswith(url) for url in iap_exempt_urls):
            return self.get_response(request)

        # If a user is already authenticated, no need to re-authenticate
        if hasattr(request, "user") and request.user.is_authenticated:
            return self.get_response(request)

        user = auth.authenticate(request)

        if user:
            request.user = user
            logger.info(f"IAP: Authenticated user {user.email}")

        return self.get_response(request)
