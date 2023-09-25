# A Node.js OAuth Agent for SPAs

[![Quality](https://img.shields.io/badge/quality-test-yellow)](https://curity.io/resources/code-examples/status/)
[![Availability](https://img.shields.io/badge/availability-source-blue)](https://curity.io/resources/code-examples/status/)

## Overview

The OAuth Agent acts as a modern `Back End for Front End (BFF)` for Single Page Applications.\
This implementation demonstrates the standard pattern for SPAs:

- Strongest browser security with only `SameSite=strict` cookies
- The OpenID Connect flow uses Authorization Code Flow (PKCE) and a client secret

![Logical Components](/doc/logical-components.png)

## Architecture

The following endpoints are implemented by the OAuth agent.\
The SPA calls these endpoints via one liners, to perform its OAuth work:

| Endpoint | Description |
| -------- | ----------- |
| GET /auth/login | Start a login by redirecting to authorize endpoint of IdP and setting temporary cookies |
| GET /auth/login/callback | Complete a login, store tokens and return userinfo to the SPA in a header |
| GET /auth/userInfo | Return ID token claims such as `auth_time` and `acr` |
| POST /auth/refresh | Refresh an access token and restore tokens |
| POST /auth/logout | Clear tokens and redirect to OIDC logout endpoint of IdP |

## Token Storage

### Access tokens

Access tokens are stored unencrypted in a secure, http-only, samesite browser cookie.

### ID tokens and refresh tokens

2 storage options are available for storing ID token and refresh tokens; `cookie` or `redis`. The default storage option is cookie. This can be configured by setting the environment variable `SESSION_STORAGE`.

If redis is configured as the storage option, redis connection details must be configured using the following environment variables.

- `REDIS_HOST` 
- `REDIS_PORT`
- `REDIS_USERNAME`
- `REDIS_PASSWORD`

The tokens will be encrypted in either case.


## Deployment

Build the OAuth agent into a Docker image:

```bash
npm install
npm run build
docker build -t oauthagent:1.0.0 .
```

Then deploy the Docker image with environment variables similar to these:

```yaml
oauth-agent:
  image: oauthagent:1.0.0
  hostname: oauthagent-host
  environment:
    PORT: 3001
    COOKIE_NAME_PREFIX: 'auth'
    COOKIE_ENCRYPTION_KEY: 'fda91643fce9af565bdc34cd965b48da75d1f5bd8846bf0910dd6d7b10f06dfe'
    SESSION_STORAGE: cookie
```

<!-- If the OAuth Agent is deployed to the web domain, then set these properties:

```yaml
COOKIE_DOMAIN: 'www.example.com'
CORS_ENABLED: 'false'
```

In development setups, HTTP URLs can be used and certificate values left blank. -->

## OAuth Agent Development

See the [Setup](/doc/Setup.md) article for details on productive OAuth Agent development.\
This enables a test driven approach to developing the OAuth Agent, without the need for a browser.
