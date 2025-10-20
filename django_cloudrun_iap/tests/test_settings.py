import os

# Minimal Django settings for running tests

# Unique secret key for testing (no need to be hidden)
SECRET_KEY = "not-a-very-secret-key"

# Define the database for running migrations and tests
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": os.path.join(os.path.dirname(__file__), "db.sqlite3"),
    }
}

# Add your app and the required Django auth apps
INSTALLED_APPS = [
    "django.contrib.sessions",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django_cloudrun_iap"
]

# Set the USER_MODEL to standard Django User
AUTH_USER_MODEL = "auth.User"

# Add the custom authentication backend
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "django_cloudrun_iap.backends.IAPAuthenticationBackend",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    'django.middleware.csrf.CsrfViewMiddleware',
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_cloudrun_iap.middlewares.IAPAuthenticationMiddleware",
]


# Minimal IAP settings needed for the middleware to run
IAP_ENABLED = True
IAP_EXPECTED_AUDIENCE = "/projects/123/locations/test/services/test-service"
IAP_EMAIL_DOMAIN = "emencia.com"
IAP_EXEMPT_URLS = ["/exempt/"]
