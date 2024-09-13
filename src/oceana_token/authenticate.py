# coding: utf-8

import requests
import json
from datetime import datetime
from decouple import config


from . import oceana_api_url, oceana_api_endpoint, oceana_api_client_id, oceana_api_client_secret, \
    oceana_api_token_timeout, oceana_api_auth_header, oceana_api_logger_level, oceana_api_logger_format

from .exceptions import OceanaError, HttpResponseError, ServiceRequestError, ClientAuthenticationError
from .utils import string_base64, base64_string


import logging
logger = logging.getLogger(__name__)


def configure_logger():
    logger_level = config("OCEANA_API_LOGGER_LEVEL", oceana_api_logger_level)
    logger_format = config("OCEANA_API_LOGGER_FORMAT", oceana_api_logger_format)
    if logger_level is not None:
        logger.setLevel(logger_level)

    if logger_format is not None:
        logger.propagate = False
        ch = logging.StreamHandler()
        formatter = logging.Formatter(logger_format)
        ch.setFormatter(formatter)
        logger.addHandler(ch)


# Configure logger when importing module
configure_logger()


class Authenticate:

    # Attributes
    _oceana_api_token: str = None
    _oceana_api_token_datetime: datetime = None
    _oceana_api_session: requests.Session = None

    def __init__(self, url=None, client_id=None, client_secret=None, keep_session=False):
        self._url = url
        self._client_id = client_id
        self._client_secret = string_base64(client_secret)
        if keep_session:
            self._oceana_api_session = requests.Session()
        # Refresh logger environment variables
        configure_logger()

    def get_token(self):
        if not self.is_token_valid():
            logger.info("Getting Oceana API token")
            self.authenticate()
        return self._oceana_api_token

    def authenticate(self):

        url, client_id, client_secret = self._get_parameters()

        url = url + f"/{oceana_api_endpoint}"

        json_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            # "grant_type": "client_credentials"
        }

        headers = {
            "Content-Type": "application/json"
        }

        try:
            if self._oceana_api_session is None:
                response = requests.post(url=url, json=json_data, headers=headers, verify=False)
            else:
                # Keep session
                response = self._oceana_api_session.post(url=url, json=json_data, headers=headers, verify=False)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if response.status_code not in [400, 401]:
                # raise HttpResponseError(f"{e.response.text}") from e
                raise HttpResponseError(message=f"{e.args[0]}", response=response) from e

        try:
            # Get response in json
            token_json = response.json()  # type: ignore
            status_code = int(token_json["code"]) if "code" in token_json.keys() and isinstance(token_json["code"], int) \
                else response.status_code
        except Exception as e:
            raise OceanaError(f"{e}")

        # Raise exception if response is not ok
        if not response.ok:
            self._response_raise_error(response, token_json, status_code)

        # Get token from response
        if status_code == 200:
            token = token_json["data"]["GetToken"]["token"]
            # Store token
            self._oceana_api_token = token
            self._oceana_api_token_datetime = datetime.now()
            logger.debug(f"Token: {self._oceana_api_token}")
            logger.debug(f"Token datetime: {self._oceana_api_token_datetime}")
            logger.info("Authentication Oceana API OK")
        else:
            # This code should never happen, cause code 200 is a response.ok
            error_msg = f"Error authenticating in Oceana API: <Response [{status_code}]>"
            logger.error(f"{error_msg}")
            raise OceanaError(error_msg)

        return response

    def is_token_valid(self, response_json=None):

        if self._oceana_api_token_datetime is not None:
            # The token has an 5 minutes validity. After that time a new token needs to be requested
            seconds_diff = (datetime.now() - self._oceana_api_token_datetime).total_seconds()
            if seconds_diff < oceana_api_token_timeout:
                return True
            elif response_json is not None:
                http_code = response_json.get("httpCode")
                http_message = response_json.get("httpMessage")
                more_information = response_json.get("moreInformation")
                if http_code != "401" and http_message != "Unauthorized" and more_information != "Invalid client id or secret":
                    return True
                else:
                    return False
        else:
            logger.debug("No token yet or token is not valid anymore")
            return False

    def authorization_header(self, headers: dict = {}) -> dict:
        """
        Update authorization header
        """
        token = self.get_token()
        headers.update({"Authorization": token} or {})
        logger.debug(f"headers: {headers}")
        return headers

    def headers(self, headers: dict = {}) -> dict:
        """
        Update common api header with token for all requests
        """
        _headers = json.loads(oceana_api_auth_header.format(token=self.get_token()))
        headers.update(_headers or {})
        logger.debug(f"headers: {headers}")
        return headers

    @property
    def session(self):
        return self._oceana_api_session

    def close_session(self):
        """
        Close requests session
        """
        if self.session is not None:
            self._oceana_api_session.close()
            self._oceana_api_session = None

    def _get_env_param(self, value, env_var, env_param, error_msg):
        if not value:
            ret_value = config(env_param, None) if env_var is None else env_var
            if ret_value is None:
                logger.error(f"{error_msg}")
                raise OceanaError(error_msg)
        else:
            ret_value = value
        return ret_value

    def _get_parameters(self):

        url = self._get_env_param(
            value=self._url,
            env_var=oceana_api_url,
            env_param="OCEANA_API_URL",
            error_msg="Oceana API url not specified. It can be set with url param " +
                      "at creation or setting environment variable OCEANA_API_URL")

        client_id = self._get_env_param(
            value=self._client_id,
            env_var=oceana_api_client_id,
            env_param="OCEANA_API_CLIENT_ID",
            error_msg="Oceana API client id not specified. It can be set with url param " +
                      "at creation or setting environment variable OCEANA_API_CLIENT_ID")

        client_secret = self._get_env_param(
            value=base64_string(self._client_secret),
            env_var=oceana_api_client_secret,
            env_param="OCEANA_API_CLIENT_SECRET",
            error_msg="Oceana API client secret not specified. It can be set with url param " +
                      "at creation or setting environment variable OCEANA_API_CLIENT_SECRET")

        return url, client_id, client_secret

    def _response_raise_error(self, response, token_json, status_code):
        try:
            error_msg = token_json["message"]
        except Exception:
            error_msg = response.reason
        logger.error(f"{error_msg}")

        if status_code == 400:
            raise ServiceRequestError(error_msg)
        elif status_code == 401:
            raise ClientAuthenticationError(error_msg)
        else:
            raise HttpResponseError(error_msg)
