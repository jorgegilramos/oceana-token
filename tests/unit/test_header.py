# coding: utf-8


import json
from oceana_token import oceana_api_auth_header


auth_header_ok = {
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Authorization": "Bearer <token>"
}


def test_auth_header_ok(mock_oceana_api_client):
    """
    Test header
    """

    headers = json.loads(oceana_api_auth_header.format(token=mock_oceana_api_client.get_token()))
    assert headers == auth_header_ok


def test_authorization_header_ok(mock_oceana_api_client):
    """
    Test authorization header
    """

    headers = mock_oceana_api_client.authorization_header(headers={})
    assert headers == {"Authorization": "Bearer <token>"}


def test_headers_ok(mock_oceana_api_client):
    """
    Test headers method
    """
    input_headers = {
        "Content-Type": "application/text",  # This value will be changed
        "Accept": "application/text",        # This value will be changed
        "Authorization": "",                 # This value will be changed
        "X-Header": "value"
    }

    headers = mock_oceana_api_client.headers(headers=input_headers)
    assert headers == {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer <token>",
        "X-Header": "value"
    }
