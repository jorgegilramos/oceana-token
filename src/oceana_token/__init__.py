# coding: utf-8

from decouple import config

oceana_api_url = config("OCEANA_API_URL", None)
oceana_api_client_id = config("OCEANA_API_CLIENT_ID", None)
oceana_api_client_secret = config("OCEANA_API_CLIENT_SECRET", None)

oceana_api_version = "v1"
oceana_api_endpoint = f"{oceana_api_version}/auth/token"

# Application will ask for a new token 10 seconds before its expiration
oceana_api_token_threshold = int(config("OCEANA_API_TOKEN_THRESHOLD", default=10))

# Oceana API token validity is 5 minutes.
oceana_api_token_timeout = 300 - oceana_api_token_threshold

# Api header with token for all requests
oceana_api_auth_header = """{{
    "Content-Type": "application/json",
    "Accept": "application/json",
    "Authorization": "{token}"
}}"""

oceana_api_logger_level = config("OCEANA_API_LOGGER_LEVEL", None)
oceana_api_logger_format = config("OCEANA_API_LOGGER_FORMAT", None)

from .authenticate import Authenticate            # noqa
from .utils import string_base64, base64_string   # noqa

__all__ = ["oceana_api_url",
           "oceana_api_version"
           "oceana_api_endpoint",
           "oceana_api_token_threshold",
           "oceana_api_token_timeout",
           "oceana_api_client_id",
           "oceana_api_client_secret",
           "oceana_api_auth_header"
           "oceana_api_logger_level",
           "oceana_api_logger_format",
           "Authenticate",
           "string_base64",
           "base64_string"]
