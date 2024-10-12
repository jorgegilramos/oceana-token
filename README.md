# oceana_token
Oceana API library to manage authentication token and headers


## Setup

Install latest version
```shell
pip install oceana_token
```

## Usage

Create authentication headers:
```python
from oceana_token import *
import json

# Authentication in Oceana API
oceana_api_client = Authenticate(url="http://127.0.0.1:5000",
                                 client_id="oceana-api-client",
                                 client_secret="bad_password")
token = oceana_api_client.get_token()

# Create headers
headers = oceana_api_client.headers(headers={})

# Add authentication header
headers = oceana_api_client.authorization_header(headers={})

# Create headers from template
headers = json.loads(oceana_api_auth_header.format(token=oceana_api_client.get_token()))
```

Request an endpoint:
```python
import requests

headers = ...

response = requests.get(url="http://127.0.0.1:5000/v1/organization/id/1", headers=headers, verify=False)
```

## Environment

Properties in environment variables:
```shell
# Example
OCEANA_API_URL="http://127.0.0.1:5000"
OCEANA_API_CLIENT_ID="oceana-api-client"
OCEANA_API_CLIENT_SECRET="bad_password"
OCEANA_API_LOGGER_LEVEL="DEBUG"
OCEANA_API_LOGGER_FORMAT="%(asctime)s - [%(name)-25s] - %(levelname)-5s - %(message)s"
```

## Packaging

Build package
```shell
# Using build package
python -m build
```


Run tests
```shell
# All tests
pytest -q -rP

# Partial tests
pytest tests/unit/test_authentication.py -v -rP
pytest tests/unit/test_header.py -v -rP
pytest tests/unit/test_jwt.py -v -rP
```

```shell
# Reinstall avoiding reinstalling dependencies
pip install --upgrade --no-deps --force-reinstall dist\oceana_token-0.0.3-py3-none-any.whl
```

```shell
# Reinstall with dependencies
pip install dist\oceana_token-0.0.3-py3-none-any.whl --force-reinstall
```

Check style guide enforcement
```shell
flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
```

## Dependencies

| Library                | Version |
|------------------------|---------|
| build                  | 1.2.1   |
| setuptools             | 67.8.0  |
| wheel                  | 0.38.4  |
| requests               | 2.29.0  |
| pytest                 | 7.4.0   |
| coverage               | 6.4.4   |
| flake8                 | 4.0.1   |
| python-decouple        | 3.8     |
| typing-extensions      | 4.12.2  |


## Releases
**Version 0.0.3**:
   - First version