## Endpoints

The following endpoints are implemented by the OAuth agent.\
The SPA calls these endpoints via one liners, to perform its OAuth work:

| Endpoint | Description |
| -------- | ----------- |
| GET /oauth-agent/login/start | Start a login by setting temporary cookies |
| POST /oauth-agent/login/callback | Complete a login by issuing secure cookies for the SPA containing encrypted tokens and redirecting to post login URL |
| GET /oauth-agent/userInfo | Return information from the User Info endpoint for the SPA to display |
| GET /oauth-agent/logout | Clear cookies and initiate OIDC logout |
| GET /oauth-agent/logout/callback | Redirect to post logout URL |
