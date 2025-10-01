from django.contrib.auth.models import AbstractUser


class IAPServiceUser(AbstractUser):
    """A minimal mock user object for authenticated IAP service accounts."""

    is_authenticated = True
    is_staff = True
    is_superuser = True
    is_anonymous = False

    def __init__(self, email):
        self.email = email

    def get_full_name(self):
        return f"Service Account: {self.email}"


