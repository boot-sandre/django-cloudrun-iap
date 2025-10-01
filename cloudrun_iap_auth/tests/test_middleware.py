from django.test import RequestFactory
from django.contrib.auth import get_user_model

from cloudrun_iap_auth.middlewares import IAPAuthenticationMiddleware


User = get_user_model()


def test_iap_middleware_valid_jwt_logs_in_user(mocker, settings, db):
    """
    Tests that a request with valid IAP headers authenticates and sets the
    correct Django user on the request object.
    """
    # 1. Setup: Create a mock user in the database
    user_email = "test.user@emencia.com"
    User.objects.create_user(
        username=user_email.split('@')[0],
        email=user_email,
        password='password123'
    )

    # 2. Mock the external Google API call
    # The verify_token function must return the decoded JWT payload
    mock_decoded_jwt = {
        "sub": "a-google-user-id",
        "email": user_email,
        "aud": settings.IAP_EXPECTED_AUDIENCE,
    }
    mocker.patch(
        "cloudrun_iap_auth.middlewares.id_token.verify_token",
        return_value=mock_decoded_jwt,
    )

    # 3. Prepare the request
    rf = RequestFactory()
    # Simulate the headers IAP sends
    iap_headers = {
        "X-Goog-Authenticated-User-Email": f"accounts.google.com:{user_email}",
        "X-Goog-IAP-JWT-Assertion": "fake-jwt-token",
    }
    request = rf.get("/", **iap_headers)

    # 4. Run the middleware
    middleware = IAPAuthenticationMiddleware(get_response=lambda r: None)
    middleware.process_request(request)

    # 5. Assertion: Check if the user was set correctly
    assert request.user.is_authenticated
    assert request.user.email == user_email
    assert request.user.pk is not None
