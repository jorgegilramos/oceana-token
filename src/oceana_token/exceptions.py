# coding: utf-8

import sys


class OceanaError(Exception):
    """
    Base exception for all errors.

    :param object message: The message object stringified as 'message' attribute
    :keyword error: The original exception if any
    :paramtype error: Exception

    :ivar inner_exception: The exception passed with the 'error' kwarg
    :vartype inner_exception: Exception
    :ivar exc_type: The exc_type from sys.exc_info()
    :ivar exc_value: The exc_value from sys.exc_info()
    :ivar exc_traceback: The exc_traceback from sys.exc_info()
    :ivar exc_msg: A string formatting of message parameter, exc_type and exc_value
    :ivar str message: A stringified version of the message parameter
    """

    def __init__(self, message, *args, **kwargs) -> None:
        self.inner_exception = kwargs.get("error")

        exc_info = sys.exc_info()
        self.exc_type = exc_info[0]
        self.exc_value = exc_info[1]
        self.exc_traceback = exc_info[2]

        self.exc_type = self.exc_type if self.exc_type else type(self.inner_exception)
        self.exc_msg: str = "{}, {}: {}".format(message, self.exc_type.__name__, self.exc_value)
        self.message: str = str(message)
        super(OceanaError, self).__init__(self.message, *args)


class ServiceRequestError(OceanaError):
    """
    An error occurred while attempt to make a request to the service.
    No request was sent.
    """


class ServiceResponseError(OceanaError):
    """
    The request was sent, but the client failed to understand the response.
    The connection may have timed out. These errors can be retried for idempotent or
    safe operations
    """


class ServiceRequestTimeoutError(ServiceRequestError):
    """
    Error raised when timeout happens
    """


class ServiceResponseTimeoutError(ServiceResponseError):
    """
    Error raised when timeout happens
    """


class HttpResponseError(OceanaError):
    """
    A request was made, and a non-success status code was received from the service.

    :param object message: The message object stringified as 'message' attribute
    :param response: The response that triggered the exception.
    """

    def __init__(self, message=None, response=None, **kwargs) -> None:

        self.reason = None
        self.status_code = None
        self.message = message
        self.response = response
        if response:
            self.reason = response.reason
            self.status_code = response.status_code

        super(HttpResponseError, self).__init__(message=message, **kwargs)


class ClientAuthenticationError(HttpResponseError):
    """
    An error response with status code 401.
    """
