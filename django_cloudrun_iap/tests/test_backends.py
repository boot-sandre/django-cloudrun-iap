import pytest
from django.test import RequestFactory
from django.contrib.auth import get_user_model
from django_cloudrun_iap.backends import IAPAuthenticationBackend
from django_cloudrun_iap.user import IAPServiceUser

User = get_user_model()

# Test data
USER_EMAIL = "test.user@emencia.com"
SERVICE_ACCOUNT_EMAIL = "test-sa@project-id.iam.gserviceaccount.com"
INVALID_DOMAIN_EMAIL = "test.user@otherdomain.com"
JWT_TOKEN = "fake-jwt-token"


@pytest.fixture
def backend():
    return IAPAuthenticationBackend()


@pytest.fixture
def rf():
    return RequestFactory()


@pytest.fixture
def create_user(db):
    return User.objects.create_user(
        username=USER_EMAIL, email=USER_EMAIL, password="password123"
    )


def mock_verify_token(mocker, email, audience):
    mock_decoded_jwt = {"sub": "a-google-user-id", "email": email, "aud": audience}
    return mocker.patch(
        "django_cloudrun_iap.backends.id_token.verify_token",
        return_value=mock_decoded_jwt,
    )


def get_request_with_headers(rf, email, token=JWT_TOKEN):
    headers = {
        "HTTP_X_GOOG_AUTHENTICATED_USER_EMAIL": f"accounts.google.com:{email}",
        "HTTP_X_GOOG_IAP_JWT_ASSERTION": token,
    }
    return rf.get("/", **headers)


def test_auth_success_user_exists(backend, rf, mocker, settings, create_user):
    """Test successful authentication for an existing user."""
    mock_verify_token(mocker, USER_EMAIL, settings.IAP_EXPECTED_AUDIENCE)
    request = get_request_with_headers(rf, USER_EMAIL)
    user = backend.authenticate(request)
    assert user is not None
    assert user.email == USER_EMAIL


def test_auth_success_service_account(backend, rf, mocker, settings):
    """Test successful authentication for a service account."""
    mock_verify_token(mocker, SERVICE_ACCOUNT_EMAIL, settings.IAP_EXPECTED_AUDIENCE)
    request = get_request_with_headers(rf, SERVICE_ACCOUNT_EMAIL)
    user = backend.authenticate(request)
    assert user is not None
    assert isinstance(user, IAPServiceUser)
    assert user.email == SERVICE_ACCOUNT_EMAIL


def test_auth_fail_no_headers(backend, rf):
    """Test authentication fails if IAP headers are missing."""
    request = rf.get("/")
    assert backend.authenticate(request) is None


def test_auth_fail_user_does_not_exist(backend, rf, mocker, settings, db):
    """Test authentication fails if user is not in the database."""
    mock_verify_token(mocker, USER_EMAIL, settings.IAP_EXPECTED_AUDIENCE)
    request = get_request_with_headers(rf, USER_EMAIL)
    assert backend.authenticate(request) is None


def test_auth_fail_jwt_validation_error(backend, rf, mocker, settings):
    """Test authentication fails if JWT validation raises an exception."""
    mocker.patch(
        "django_cloudrun_iap.backends.id_token.verify_token",
        side_effect=Exception("Invalid token"),
    )
    request = get_request_with_headers(rf, USER_EMAIL)
    assert backend.authenticate(request) is None


def test_auth_fail_email_mismatch(backend, rf, mocker, settings):
    """Test authentication fails if header and JWT emails do not match."""
    mock_verify_token(mocker, "jwt-email@emencia.com", settings.IAP_EXPECTED_AUDIENCE)
    request = get_request_with_headers(rf, "header-email@emencia.com")
    assert backend.authenticate(request) is None


def test_auth_fail_invalid_domain(backend, rf, mocker, settings):
    """Test authentication fails for users from a non-whitelisted domain."""
    mock_verify_token(mocker, INVALID_DOMAIN_EMAIL, settings.IAP_EXPECTED_AUDIENCE)
    request = get_request_with_headers(rf, INVALID_DOMAIN_EMAIL)
    assert backend.authenticate(request) is None


def test_get_user(backend, create_user):
    """Test the get_user method."""
    retrieved_user = backend.get_user(create_user.pk)
    assert retrieved_user == create_user


def test_get_user_does_not_exist(backend, db):
    """Test get_user returns None for a non-existent user ID."""
    assert backend.get_user(999) is None

def test_auth_success_mock_verification(backend, rf, mocker, settings, create_user):
    """Test successful authentication when IAP_MOCK_VERIFICATION is True."""
    settings.IAP_MOCK_VERIFICATION = True

    # Mock verify_token just to ensure it's NOT called
    mock_verify = mock_verify_token(mocker, USER_EMAIL, settings.IAP_EXPECTED_AUDIENCE)
    # Make it fail if it's ever called during this test
    mock_verify.side_effect = Exception("Should not be called in mock mode")

    request = get_request_with_headers(rf, USER_EMAIL)
    user = backend.authenticate(request)

    assert user is not None
    assert user.email == USER_EMAIL
    mock_verify.assert_not_called() 
