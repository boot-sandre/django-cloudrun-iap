from django.db import models


class IAPUserMixins:
    iap_external_id = models.CharField(
        max_length=255,
        unique=True,
        null=True,
        blank=True,
        help_text="External ID for IAP. Used for identification and linking.",
    )
    is_iap_service_account = models.BooleanField(
        default=False,
        help_text="Designates if this user record is an IAP service account.",
    )

    @property
    def is_iap(self):
        return bool(self.is_iap_service_account or self.iap_external_id)


class IAPServiceUser:
    """A minimal mock user object for authenticated IAP service accounts."""

    is_authenticated = True
    is_active = True
    is_staff = True
    is_superuser = True
    is_anonymous = False

    is_scim = True
    is_iap_service_account = True
    is_iap = True

    def __init__(self, email, username=None):
        self.email = email
        self.username = username or email.split("@")[0]

        # Mock the specific properties from the real User model
        self.iap_external_id = email if self.is_iap_service_account else None
        self.scim_external_id = "mock-scim-id" if self.is_scim else None

    def save(self, *args, **kwargs):
        """Mock the save method to prevent accidental database writes in tests."""
        pass

    def __str__(self):
        return self.email

    def get_full_name(self):
        return f"Service Account: {self.email}"


class MockAuthenticatedUser:
    """
    A minimal mock object for an authenticated user, usable in requests/tests.
    It simulates an instance of the combined User model, including SCIM/IAP properties.
    """

    # Mimic core Django User attributes for an authenticated state
    is_authenticated = True
    is_active = True

    # Mock permissions/status
    is_staff = True
    is_superuser = True
    is_anonymous = False
