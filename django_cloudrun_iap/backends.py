import logging
import time
import re

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from google.auth.transport import requests
from google.oauth2 import id_token

from .user import IAPServiceUser

logger = logging.getLogger(__name__)

# Match GCP service account user
SERVICE_ACCOUNT_REGEX = re.compile(r"^[^@]+@(.+\.)?gserviceaccount\.com$")

# IAP provides these headers after successful authentication
IAP_USER_EMAIL_HEADER = "X-Goog-Authenticated-User-Email"
IAP_JWT_ASSERTION_HEADER = "X-Goog-IAP-JWT-Assertion"


class IAPAuthenticationBackend(ModelBackend):
    """
    Custom Django authentication backend for Google Cloud IAP.

    This backend authenticates a user based on the headers provided by IAP.
    """

    def authenticate(self, request):
        """
        Authenticate the user using IAP headers.
        """
        # Fetch IAP headers
        logger.debug(
            "request.META",
            time.ctime(),
            extra={'json_fields': request.META}
        )
        iap_user_email = request.META.get(IAP_USER_EMAIL_HEADER)
        iap_jwt = request.META.get(IAP_JWT_ASSERTION_HEADER)

        if not all([iap_user_email, iap_jwt]):
            logger.debug("IAP: Missing IAP headers. Cannot authenticate.")
            return None

        # Get the expected audience from Django settings
        expected_audience = getattr(settings, "IAP_EXPECTED_AUDIENCE", None)
        if not expected_audience:
            logger.error("IAP: IAP_EXPECTED_AUDIENCE is not set.")
            return None

        # Validate the IAP JWT
        try:
            decoded_jwt = id_token.verify_token(
                iap_jwt,
                requests.Request(),
                audience=expected_audience,
                certs_url="https://www.gstatic.com/iap/verify/public_key",
            )
            decoded_email = decoded_jwt["email"]
        except Exception as e:
            logger.error(f"IAP: JWT validation failed: {e}")
            return None

        # NOTA BENE: Email is provided with the jwt which ensure that the headers
        # value not have been manipulated. In the case of mismatch it's can be an
        # application like hijack which already define the request django user.
        header_email = iap_user_email.split(":")[-1]
        if decoded_email != header_email:
            logger.error(
                f"IAP: Email mismatch: JWT ({decoded_email}) vs header ({header_email})."
            )
            return None

        # From the prefix of the email value we will deduce username
        email = decoded_email

        # Check if it's a GCP service account
        if bool(SERVICE_ACCOUNT_REGEX.match(email)):
            # Use a mock user for service accounts
            logger.info(
                "IAP headers provide GCP service account user."
                "We set a mocked user to allow request"
            )
            return IAPServiceUser(email=email)

        # Validate email domain
        # (Optional, at None as default value the check is not applied)
        iap_email_domain = getattr(settings, "IAP_EMAIL_DOMAIN", None)
        if isinstance(iap_email_domain, list):
            iap_email_domain = tuple(iap_email_domain)
        if iap_email_domain and not email.endswith(iap_email_domain):
            logger.error(f"IAP: Email from unexpected domain: {email}")
            return None

        User = get_user_model()
        try:
            user = User.objects.get(email=email)
            return user
        except User.DoesNotExist:
            logger.error(f"IAP: User with email {email} not found in DB.")
            return None
        except Exception as e:
            logger.error(f"IAP: Error retrieving user: {email} exception: {e}")
            return None

    def get_user(self, user_id):
        """
        Get a user by their primary key.
        """
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
