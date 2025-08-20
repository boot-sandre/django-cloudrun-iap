# django_iap_auth/middleware.py
import logging
from django.contrib.auth import login, get_user_model
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.db.models import Q

from google.auth.transport import requests
from google.oauth2 import id_token


logger = logging.getLogger(__name__)


class IAPAuthenticationMiddleware(MiddlewareMixin):
    """
    Middleware for authenticating users via Google Cloud IAP.

    This middleware intercepts requests, validates the IAP headers, and logs
    in the corresponding Django user based on the email provided by IAP.
    It assumes the Django User model uses 'email' as a unique identifier.
    """

    def _validate_iap_jwt(self, iap_jwt, expected_audience):
        """Validate an IAP JWT."""
        try:
            decoded_jwt = id_token.verify_token(
                iap_jwt,
                requests.Request(),
                audience=expected_audience,
                certs_url="https://www.gstatic.com/iap/verify/public_key",
            )
            return (decoded_jwt["sub"], decoded_jwt["email"], "")
        except Exception as e:
            return (None, None, f"**ERROR: JWT validation error {e}**")

    def process_request(self, request):
        if not getattr(settings, "IAP_ENABLED", False):
            # IAP is not enabled, skip this middleware
            return

        # IAP provides these headers after successful authentication
        iap_user_email_header = "X-Goog-Authenticated-User-Email"
        iap_jwt_assertion_header = "X-Goog-IAP-JWT-Assertion"

        iap_user_email = request.headers.get(iap_user_email_header)
        iap_jwt = request.headers.get(iap_jwt_assertion_header)

        # Ensure all necessary IAP headers are present
        if not all([iap_user_email, iap_jwt]):
            logger.debug(
                "IAP: Missing one or more IAP headers. Skipping IAP authentication."
            )
            return

        # Get the expected audience from Django settings
        expected_audience = getattr(settings, "IAP_EXPECTED_AUDIENCE", None)
        if not expected_audience:
            logger.error(
                "IAP: IAP_EXPECTED_AUDIENCE is not set in settings. Cannot validate JWT."
            )
            return HttpResponseForbidden("IAP authentication misconfigured.")

        # Validate the IAP JWT
        _, decoded_email, error_str = self._validate_iap_jwt(iap_jwt, expected_audience)

        if error_str:
            logger.error(f"IAP: JWT validation failed: {error_str}")
            return HttpResponseForbidden("IAP JWT validation failed.")

        # The IAP user email header is formatted as 'accounts.google.com:user@example.com'
        # The email from the JWT should also match.
        header_email = iap_user_email.split(":")[-1]
        if decoded_email != header_email:
            logger.error(
                f"IAP: Email mismatch between JWT ({decoded_email}) and header ({header_email})."
            )
            return HttpResponseForbidden("Email mismatch in IAP headers.")

        email = decoded_email

        # Optional: Validate the email domain if specified in settings
        iap_email_domain = getattr(settings, "IAP_EMAIL_DOMAIN", None)
        if iap_email_domain and not email.endswith(f"@{iap_email_domain}"):
            logger.warning(f"IAP: Received email from unexpected domain: {email}")
            return HttpResponseForbidden(
                f"Bad IAP user domain. Must be @{iap_email_domain} but received {email}"
            )

        User = get_user_model()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.error(
                f"IAP: User authenticated by IAP not found in Django DB with email: {email}"
            )
            return HttpResponseForbidden("User not found in application database.")
        except Exception as e:
            logger.error(f"IAP: Error retrieving user from DB: {e}")
            return HttpResponseForbidden(
                "Internal server error during IAP authentication."
            )

        # Log the user in if they aren't already authenticated as this user.
        if not request.user.is_authenticated or request.user != user:
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            logger.debug(f"IAP: User {email} logged in.")
