# oauth2-rp

Simple and easily hackable reverse proxy to use for [Rundeck in Preauthenticated Mode using headers](https://docs.rundeck.com/docs/administration/security/authentication.html#preauthenticated-mode-using-ajp-with-apache-and-tomcat) against non-IODC OAuth2 backend.


## Config

as env vars or via `.env` file

### OAuth2 app def

```bash
CLIENT_ID=''
CLIENT_SECRET=''
ACCESS_TOKEN_URI=http://localhost:8080/auth/realms/testrealm/protocol/openid-connect/token
AUTHORIZATION_URI=http://localhost:8080/auth/realms/testrealm/protocol/openid-connect/auth
USERINFO_URI=http://localhost:8080/auth/realms/testrealm/protocol/openid-connect/userinfo
SCOPES='basic'
```

### Redirect URL (configured provider side)
 ex: http://localhost:3000/oauth/callback

```bash
REDIRECT_URI='<proto>://this instance exposed name or ip:port/oauth/callback'
```

### Proxied service (ex rundeck)

```bash
RP_TARGET=http://localhost:4440
```

### if SSL enabled

```bash
KEY_FILE=certs/key.pem
CERT_FILE=certs/cert.pem
```

## Todo

- [ ] Use NaCL secret box to make the proxy fully stateless
- [ ] Add X-Forwarded-(Proto|For|Host) ?
- [ ] Reorganize / cleanup
