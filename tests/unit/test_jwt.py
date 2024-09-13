# coding: utf-8

import json
import jwt
from datetime import datetime, timedelta
import requests
import pytest
import requests_mock

from oceana_token import oceana_api_auth_header


APP_OCEANA_API_NAME = "OceanaAPI"
APP_OCEANA_API_TOKEN_VERSION = "v1"
OCEANA_API_TOKEN_MAX_MINUTES = 60
APP_OCEANA_API_SECRET_KEY = "OCEANA_SECRET_KEY"  # Obviously this is not the real key!!!


def generate_jwt(payload, lifetime=None):
    """
    Generates a new JWT token, wrapping information provided by payload (dict)
    Lifetime describes (in minutes) how much time the token will be valid
    """

    # Issuer is OceanaAPI
    payload["iss"] = APP_OCEANA_API_NAME
    payload["created"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload["version"] = APP_OCEANA_API_TOKEN_VERSION

    # Set max minutes duration if lifetime is None
    lifetime = OCEANA_API_TOKEN_MAX_MINUTES if lifetime is None else lifetime

    if lifetime:
        valid_until = (datetime.now() + timedelta(minutes=lifetime))
        payload["exp"] = valid_until.timestamp()
        payload["valid_until"] = valid_until.strftime("%Y-%m-%d %H:%M:%S")
    else:
        # Lifetime will have a control mechanism
        raise Exception("No eternal tokens allowed")
    return jwt.encode(payload, APP_OCEANA_API_SECRET_KEY, algorithm="HS256")


def decode_jwt(token):
    """
    Tries to retrieve payload information inside of a existent JWT token (string)
    Will throw an error if the token is invalid (expired or inconsistent)
    """

    return jwt.decode(token, APP_OCEANA_API_SECRET_KEY, algorithms=["HS256"])


def check_jwt(headers):
    """
    Gets token from request header and tries to get it's payload
    Will raise errors if token is missing, invalid or expired
    """

    token = headers.get("Authorization")
    if not token:
        raise Exception("Missing access token")

    if not token.startswith("Bearer "):
        raise Exception("Authorization header must follow pattern \"Bearer <token_value>\"")
    jwt = token.split("Bearer ")[1]

    try:
        return decode_jwt(jwt)
    except Exception as e:
        # Also throws exception "Signature has expired"
        raise Exception(f"Invalid access token: {e}")


def test_jwt_token_ok():
    """
    Test JWT
    """

    payload = {
        "client_id": "oceana-api-client",
        "client_type": "application",
        "roles": ["reader", "writer"]
    }

    token = generate_jwt(payload=payload)
    payload_decoded = decode_jwt(token)
    print(payload_decoded)

    # version = payload_decoded.pop("version")
    # iss = payload_decoded.pop("iss")
    # created = payload_decoded.pop("created")
    # exp = payload_decoded.pop("exp")
    # valid_until = payload_decoded.pop("valid_until")
    assert payload_decoded == payload


json_response_unauthorized_error = {
    "data": {
        "GetOrganizationUnitsById": None
    },
    "message": "Authorization required",
    "status": "ERROR",
    "code": 403
}


@pytest.fixture
def mock_auth_token_endpoint():
    with requests_mock.Mocker() as requests_mocker:

        def match_organization_jwt_client1(request):
            payload = check_jwt(headers=request.headers)
            # print(payload)
            return payload["client_id"] == "oceana-api-client1" and payload["client_type"] == "application" and \
                payload["iss"] == APP_OCEANA_API_NAME and payload["version"] == APP_OCEANA_API_TOKEN_VERSION and \
                "reader" in payload["roles"]

        def match_organization_jwt_client2(request):
            payload = check_jwt(headers=request.headers)
            # print(payload)
            return payload["client_id"] == "oceana-api-client2" and payload["client_type"] == "application" and \
                payload["iss"] == APP_OCEANA_API_NAME and payload["version"] == APP_OCEANA_API_TOKEN_VERSION and \
                "reader" not in payload["roles"]

        requests_mocker.get("http://127.0.0.1:5000/v1/organization/id/1",
                            additional_matcher=match_organization_jwt_client1, status_code=200, json={})
        requests_mocker.get("http://127.0.0.1:5000/v1/organization/id/1",
                            additional_matcher=match_organization_jwt_client2, status_code=403,
                            json=json_response_unauthorized_error)
        yield


def test_endpoint_jwt_ok(mock_auth_token_endpoint):

    endpoint_url = "http://127.0.0.1:5000/v1/organization/id/1"
    payload = {
        "client_id": "oceana-api-client1",
        "client_type": "application",
        "roles": ["reader", "writer"]
    }

    token = f"Bearer {generate_jwt(payload=payload)}"
    headers = json.loads(oceana_api_auth_header.format(token=token))
    print(headers)
    response = requests.get(url=endpoint_url, headers=headers, verify=False)
    assert response.status_code == 200
    assert response.json() == {}


def test_endpoint_jwt_unauthorized(mock_auth_token_endpoint):

    endpoint_url = "http://127.0.0.1:5000/v1/organization/id/1"
    payload = {
        "client_id": "oceana-api-client2",
        "client_type": "application",
        "roles": []
    }

    token = f"Bearer {generate_jwt(payload=payload)}"
    headers = json.loads(oceana_api_auth_header.format(token=token))
    print(headers)
    response = requests.get(url=endpoint_url, headers=headers, verify=False)
    assert response.status_code == 403
    assert response.json() == json_response_unauthorized_error
