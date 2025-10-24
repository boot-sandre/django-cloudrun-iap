from django.test import RequestFactory
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.contrib.sessions.middleware import SessionMiddleware
from django_cloudrun_iap.middlewares import IAPAuthenticationMiddleware


User = get_user_model()


def get_response_mock(request):
    """A mock get_response function."""
    return None


def test_middleware_authenticates_user(mocker, settings, db):
    """
    Test that the middleware calls auth.authenticate and sets request.user.
    """
    user_email = "test.user@emencia.com"
    user = User.objects.create_user(username=user_email, email=user_email)
    
    user.backend = 'django_cloudrun_iap.backends.IAPAuthenticationBackend'

    mock_authenticate = mocker.patch(
        "django_cloudrun_iap.middlewares.auth.authenticate", return_value=user
    )

    rf = RequestFactory()
    request = rf.get("/")
    request.user = AnonymousUser()

    session_mw = SessionMiddleware(get_response_mock)
    session_mw(request)
    # The session must be saved for auth.login to use it
    request.session.save()

    middleware = IAPAuthenticationMiddleware(get_response=get_response_mock)
    middleware(request)

    mock_authenticate.assert_called_once_with(request)
    assert request.user == user


def test_middleware_iap_disabled(mocker, settings):
    """Test that the middleware does nothing if IAP_ENABLED is False."""
    settings.IAP_ENABLED = False
    mock_authenticate = mocker.patch("django_cloudrun_iap.middlewares.auth.authenticate")

    rf = RequestFactory()
    request = rf.get("/")

    middleware = IAPAuthenticationMiddleware(get_response=get_response_mock)
    middleware(request)

    mock_authenticate.assert_not_called()


def test_middleware_exempt_url(mocker, settings):
    """Test that the middleware bypasses auth for exempt URLs."""
    mock_authenticate = mocker.patch("django_cloudrun_iap.middlewares.auth.authenticate")

    rf = RequestFactory()
    request = rf.get("/exempt/")  # This URL is in IAP_EXEMPT_URLS

    middleware = IAPAuthenticationMiddleware(get_response=get_response_mock)
    middleware(request)

    mock_authenticate.assert_not_called()


def test_middleware_user_already_authenticated(mocker, db):
    """Test that the middleware does nothing if a user is already authenticated."""
    user_email = "test.user@emencia.com"
    user = User.objects.create_user(username=user_email, email=user_email)

    mock_authenticate = mocker.patch("django_cloudrun_iap.middlewares.auth.authenticate")

    rf = RequestFactory()
    request = rf.get("/")
    request.user = user  # Set an authenticated user on the request

    middleware = IAPAuthenticationMiddleware(get_response=get_response_mock)
    middleware(request)

    mock_authenticate.assert_not_called()
