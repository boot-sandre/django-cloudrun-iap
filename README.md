# Django Cloud Run IAP Authentication Middleware

This package provides a simple Django middleware to authenticate users via
Google Cloud's Identity-Aware Proxy (IAP), specifically tailored for
Cloud Run deployments.

## Installation

```bash
pip install -e git+[https://github.com/boot-sandre/django-cloudrun-iap.git](https://github.com/boot-sandre/django-cloudrun-iap.git#egg=django-cloudrun-iap)
```

Or after publishing to python pypi registry:

```bash
pip install django-cloudrun-iap
```

## Configuration

To integrate `django_cloudrun_iap` into your Django project, follow these steps to modify your `settings.py` file.

### 1. Add to INSTALLED_APPS

First, add `django_cloudrun_iap` to your **`INSTALLED_APPS`** list to register the application with your project.

```python
# settings.py
INSTALLED_APPS = [
    # ... other apps
    'django_cloudrun_iap',
]
```

### 2. Add Middleware

Next, insert the IAP middleware into your MIDDLEWARE list. It is crucial to place it immediately after Django's built-in AuthenticationMiddleware.

```python
# settings.py
MIDDLEWARE = [
    # ... other middlewares
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_cloudrun_iap.middlewares.IAPAuthenticationMiddleware',
    # ... other middlewares
]
```

### 3. Configure IAP Settings

Finally, add the following configuration variables to your settings.py file.

```python
# settings.py

# Toggle the IAP middleware. Set to False to disable IAP authentication.
IAP_ENABLED = True

# The audience claim for your IAP-secured resource. This value can be found
# in your Google Cloud Console under the IAP settings for your resource.
# Format: /projects/$PROJECT_NUMBER/locations/$REGION/services/$SERVICE
IAP_EXPECTED_AUDIENCE = '/projects/123456789123/locations/europe-west1/services/myawesomedjango'

# (Optional) Restrict logins to a specific Google Workspace or Cloud Identity domain.
# Can use a string, a list of domain, or a tuple
IAP_EMAIL_DOMAIN = ["emencia.com", "velops.eu"]

IAP_EXEMPT_URLS = [
    "/api/healthcheck/",
    "/status/"
]
```

## Usage

The middleware checks for the presence of specific headers provided by
Google Cloud IAP. It then validates the JWT to ensure the request is legitimate
and comes from a trusted source. Finally, it matches the user's email to a
Django user account and logs them in.

