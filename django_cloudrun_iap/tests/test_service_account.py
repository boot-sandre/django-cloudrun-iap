from django.test import RequestFactory
from django.contrib.auth.models import AnonymousUser
from django_cloudrun_iap.middlewares import IAPAuthenticationMiddleware
from django_cloudrun_iap.user import IAPServiceUser

SERVICE_ACCOUNT_EMAIL = "test-sa@project-id.iam.gserviceaccount.com"


def get_response_mock(request):
    """A mock get_response function."""
    return None


def test_middleware_authenticates_service_account(mocker, settings):
    """
    Test that the middleware authenticates a service account and sets it on the request.
    """
    service_account_user = IAPServiceUser(email=SERVICE_ACCOUNT_EMAIL)

    # Mock django.contrib.auth.authenticate to return our service account user
    mock_authenticate = mocker.patch(
        "django_cloudrun_iap.middlewares.auth.authenticate", return_value=service_account_user
    )

    rf = RequestFactory()
    request = rf.get("/")
    request.user = AnonymousUser()

    middleware = IAPAuthenticationMiddleware(get_response=get_response_mock)
    middleware(request)

    mock_authenticate.assert_called_once_with(request)
    assert request.user == service_account_user
    assert isinstance(request.user, IAPServiceUser)
    assert request.user.email == SERVICE_ACCOUNT_EMAIL


def test_middleware_service_account_already_authenticated(mocker):
    """
    Test that the middleware does nothing if a service account is already authenticated.
    """
    service_account_user = IAPServiceUser(email=SERVICE_ACCOUNT_EMAIL)

    mock_authenticate = mocker.patch("django_cloudrun_iap.middlewares.auth.authenticate")

    rf = RequestFactory()
    request = rf.get("/")
    request.user = service_account_user  # Set an authenticated service account on the request

    middleware = IAPAuthenticationMiddleware(get_response=get_response_mock)
    middleware(request)

    mock_authenticate.assert_not_called()
