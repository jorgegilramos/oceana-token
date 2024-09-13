# coding: utf-8


import pytest

from oceana_token import Authenticate
from oceana_token.exceptions import OceanaError, ClientAuthenticationError


# This fixture has to be in this file because monkeypath is not allowed with a session scoped request object
@pytest.fixture
def mock_env_variables(monkeypatch):

    monkeypatch.setenv("OCEANA_API_URL", "http://127.0.0.1:5000")
    monkeypatch.setenv("OCEANA_API_CLIENT_ID", "oceana-api-client")
    monkeypatch.setenv("OCEANA_API_CLIENT_SECRET", "bad_password")
    monkeypatch.setenv("OCEANA_API_LOGGER_LEVEL", "DEBUG")
    monkeypatch.setenv("OCEANA_API_LOGGER_FORMAT", "%(asctime)s - [%(name)-25s] - %(levelname)-5s - %(message)s")
    yield
    # Teardown
    # print("Teardown")
    # monkeypatch.delenv("OCEANA_API_LOGGER_LEVEL")
    # monkeypatch.delenv("OCEANA_API_LOGGER_FORMAT")


def test_get_token_env_ok(mock_env_variables):
    """
    Authentication in Oceana API from environment variables
    """

    # import os
    # print(os.environ["OCEANA_API_URL"])
    # print(os.environ["OCEANA_API_CLIENT_ID"])
    # print(os.environ["OCEANA_API_CLIENT_SECRET"])
    # print(os.environ["OCEANA_API_LOGGER_LEVEL"])
    # print(os.environ["OCEANA_API_LOGGER_FORMAT"])

    # Authentication in Oceana API
    oceana_api_client = Authenticate()
    token = oceana_api_client.get_token()
    assert token == "Bearer <token>"


def test_get_token_parameters_ok():
    """
    Authentication in Oceana API from parameters
    """

    # Authentication in Oceana API
    oceana_api_client = Authenticate(url="http://127.0.0.1:5000",
                                     client_id="oceana-api-client",
                                     client_secret="bad_password")
    token = oceana_api_client.get_token()
    assert token == "Bearer <token>"


def test_get_token_missing_exception():
    """
    Authentication error in Oceana API from parameters
    """

    # Authentication in Oceana API
    oceana_api_client = Authenticate(url="http://127.0.0.1:5000",
                                     client_id="oceana-api-client",
                                     client_secret="")
    # Validate exception
    with pytest.raises(OceanaError) as exc_info:
        oceana_api_client.get_token()
    assert str(exc_info.value) == "Oceana API client secret not specified. It can be set with url param " + \
        "at creation or setting environment variable OCEANA_API_CLIENT_SECRET"


def test_get_token_credential_exception():
    """
    Authentication error in Oceana API from parameters
    """

    # Authentication in Oceana API
    oceana_api_client = Authenticate(url="http://127.0.0.1:5000",
                                     client_id="oceana-api-client",
                                     client_secret="error_password")
    # Validate exception
    with pytest.raises(ClientAuthenticationError) as exc_info:
        oceana_api_client.get_token()
    assert str(exc_info.value) == "Oceana API invalid credentials for client id: oceana-api-client"
