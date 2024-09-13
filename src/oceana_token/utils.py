# coding: utf-8

import base64


def string_base64(s):
    return base64.b64encode(s.encode("utf-8")) if isinstance(s, str) else None


def base64_string(b):
    return base64.b64decode(b).decode("utf-8") if isinstance(b, bytes) else None
