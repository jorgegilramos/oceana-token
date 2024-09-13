# coding: utf-8

import pytest
import requests_mock
from oceana_token import Authenticate


json_response_ok = {
    "data": {
        "GetToken": {
            "token": "Bearer <token>"
        }
    },
    "status": "OK",
    "code": 200
}

json_data_ok = {
    "client_id": "oceana-api-client",
    "client_secret": "bad_password"
}

json_data_credential_error = {
    "client_id": "oceana-api-client",
    "client_secret": "error_password"
}


json_response_credentials_error = {
    "data": {
        "GetToken": None
    },
    "message": "Oceana API invalid credentials for client id: oceana-api-client",
    "status": "ERROR",
    "code": 401
}


@pytest.fixture(scope="session", autouse=True)
def mock_auth_token_endpoint():
    with requests_mock.Mocker() as requests_mocker:
        def match_data_ok(request):
            return request.json() == json_data_ok

        def match_data_credential_error(request):
            return request.json() == json_data_credential_error
        
        requests_mocker.post(f"http://127.0.0.1:5000/v1/auth/token", additional_matcher=match_data_ok, status_code=200, json=json_response_ok)
        requests_mocker.post(f"http://127.0.0.1:5000/v1/auth/token", additional_matcher=match_data_credential_error, status_code=401, json=json_response_credentials_error)
        yield


@pytest.fixture(scope="module", autouse=True)
def mock_oceana_api_client():

    # Authentication in Oceana API
    api_client = Authenticate(url="http://127.0.0.1:5000",
                                    client_id="oceana-api-client",
                                    client_secret="bad_password")
    yield api_client
