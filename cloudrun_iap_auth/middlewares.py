import logging
import re
from django.contrib.auth import get_user_model
from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings

from google.auth.transport import requests
from google.oauth2 import id_token

from .mock import IAPServiceUser

logger = logging.getLogger(__name__)


# Match GCP service account user
SERVICE_ACCOUNT_REGEX = re.compile(r"^[^@]+@(.+\.)?gserviceaccount\.com$")

# IAP provides these headers after successful authentication
IAP_USER_EMAIL_HEADER = "X-Goog-Authenticated-User-Email"
IAP_JWT_ASSERTION_HEADER = "X-Goog-IAP-JWT-Assertion"


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
        # Check if IAP is enabled
        if not getattr(settings, "IAP_ENABLED", False):
            logger.debug("IAP is desactivated. looks dj settings IAP_ENABLED")
            return
        logger.debug("IAP is activated by IAP_ENABLED dj settings")

        # Check for public URL exceptions
        iap_exempt_urls = getattr(settings, "IAP_EXEMPT_URLS", [])
        logger.debug(f"IAP_EXEMPT_URLS: {iap_exempt_urls}")
        for url_pattern in iap_exempt_urls:
            if request.path.startswith(url_pattern):
                logger.info(
                    f"IAP: Bypassing authentication for exempt URL: {request.path}"
                )
                return

        # Fetch IAP headers
        iap_user_email = request.META.get(IAP_USER_EMAIL_HEADER)
        iap_jwt = request.META.get(IAP_JWT_ASSERTION_HEADER)
        logger.debug(f"iap_user_email from HTTP HEADERS {iap_user_email}")

        # Ensure all necessary IAP headers are present
        if not all([iap_user_email, iap_jwt]):
            logger.debug(
                "IAP: Missing one or more IAP headers. Skipping IAP authentication."
            )
            return

        # Get the expected audience from Django settings
        expected_audience = getattr(settings, "IAP_EXPECTED_AUDIENCE", None)
        logger.debug(f"IAP_EXPECTED_AUDIENCE: {expected_audience}")
        if not expected_audience:
            logger.error(
                "IAP: IAP_EXPECTED_AUDIENCE is not set in settings. Cannot validate JWT."
            )
            return HttpResponseForbidden("IAP authentication misconfigured.")

        # Validate the IAP JWT
        _, decoded_email, error_str = self._validate_iap_jwt(iap_jwt, expected_audience)
        logger.debug(f"decoded email from jwt: {decoded_email}")
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

        iap_email_domain = getattr(settings, "IAP_EMAIL_DOMAIN", None)
        logger.debug(
            f"IAP email domain from django settings (tuple, list or None): {iap_email_domain}"
        )
        # Cast correctly settings, endswith accept or a string, or a tuple.
        if type(iap_email_domain) is list:
            iap_email_domain = tuple(iap_email_domain)

        if iap_email_domain and not email.endswith(iap_email_domain):
            logger.error(f"IAP: Received email from unexpected domain: {email}")
            return HttpResponseForbidden(
                f"Bad IAP user domain. Must be @{iap_email_domain} but received {email}"
            )

        self.set_iap_django_user(request, email)
        logger.debug(f"IAP: user {request.user.email} set on django request.")

    def set_iap_django_user(self, request, email):
        user = self.iap_django_user(email)
        if hasattr(request, "user") and request.user:
            if request.user.email == user.email:
                logger.info(
                    "User identified by IAP settings is already set on request django object."
                )
                return
            logger.warning(
                f"User provide by IAP headers ({user.email}) is mismatching "
                f"user setted on django request ({request.user.email})."
                "We will override request.user property."
            )
        logger.info(
            f"Set request.user to the user ({user.email}) object matching with IAP authentification headers."
        )
        request.user = user

    def iap_django_user(self, email: str):
        User = get_user_model()
        is_gcp_service_account = bool(SERVICE_ACCOUNT_REGEX.match(email))
        if is_gcp_service_account:
            logger.debug(
                f"IAP: Authenticated a GCP service account: {email}. Creating in-memory user object."
            )
            logger.debug(f"IAP: GCP Service account {email}.")
            # Use herited user model instead of default application user model
            User = IAPServiceUser

        # Fetch the user
        user = None
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            if is_gcp_service_account:
                user = User.objects.create_user(
                    username=email,
                    email=email,
                    password=None,
                )
            else:
                logger.error(
                    f"IAP: User authenticated by IAP not found in Django DB with email: {email}"
                )
                return HttpResponseForbidden("User not found in application database.")
        except Exception as e:
            logger.error(f"IAP: Error retrieving user from DB: {e}")
            return HttpResponseForbidden(
                "Internal server error during IAP authentication."
            )
        return user
