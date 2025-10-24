import logging
from django.contrib import auth
from django.conf import settings
from django_cloudrun_iap.user import IAPServiceUser

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
            if isinstance(user, IAPServiceUser):
                request.user = user
                logger.info(f"IAP: Authenticated service account {user.email}")
            else:
                # It's a real Django user.
                auth.login(request, user)
                logger.info(f"IAP: Authenticated and logged in user {user.email}")
        else:
            # Backend returned None (e.g., bad headers, user not in DB).
            # request.user remains AnonymousUser.
            logger.warning("IAP: Authentication via backend failed.")

        return self.get_response(request)
