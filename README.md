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
LOGOUT_URI='http://localhost:8080/auth/realms/testrealm/protocol/openid-connect/logout?id_token_hint={id_token}'
SCOPES='basic'

ROLE_RADIX=rundeck
```

* `ROLE_RADIX` is used as part of a regexp (`^(${process.env.ROLE_RADIX||"rundeck"}-[^,]+)`) to filter groups (default: `rundeck`, therefore groups should start with `rundeck-`. ie: `rundeck-admin`)
* `LOGOUT_URI`: if provided, the URI will be called as target of an iframe on the logout page. This allows the browser to trigger a logout on the SSO side. `{id_token}` is used as placeholder for the `id_token`.

### Secret generation

```bash
openssl rand -base64 32
```


### Redirect URL (configured provider side)
 ex: http://localhost:3000/oauth/callback

```bash
REDIRECT_URI='<proto>://this instance exposed name or ip:port/oauth/callback'
```

### Proxied service (ex rundeck)

```bash
RP_TARGET=https://localhost:4443
SECURE=true or false
```
`SECURE=false` allows to skip certificate's backend check given that rundeck should be binded on 127.0.0.1 for security reasons

### if SSL enabled

```bash
KEY_FILE=certs/key.pem
CERT_FILE=certs/cert.pem
```

## Installation

```bash
git clone https://github.com/babs/oauth2-rp.git /opt/oauth2-rp
cd /opt/oauth2-rp; pnpm i || yarn install || npm i # based on the pm you have/prefer
adduser --system oauth2-rp --home /opt/oauth2-rp
usermod -a -G ssl-cert oauth2-rp # for key/cert access
ln -s /opt/oauth2-rp/oauth2-rp.service /etc/systemd/system/oauth2-rp.service
# Create and customize your /opt/oauth2-rp/.env file (see env.dist)
# Once done, reload systemctl and start the service
systemctl daemon-reload
systemctl enable --now oauth2-rp || systemctl start oauth2-rp
systemctl status oauth2-rp
```

## rundeck-config.properties example

```bash
rundeck.security.authorization.preauthenticated.enabled=true
rundeck.security.authorization.preauthenticated.redirectLogout=true
rundeck.security.authorization.preauthenticated.redirectUrl=/oauth/logout
rundeck.security.authorization.preauthenticated.userNameHeader=X-Forwarded-User
rundeck.security.authorization.preauthenticated.userRolesHeader=X-Forwarded-Groups
rundeck.logout.redirect.url=https://public_hostname/oauth/logout
rundeck.login.localLogin.enabled=false
```

## Todo

- [ ] Use NaCL secret box to make the proxy fully stateless
- [ ] Add X-Forwarded-(Proto|For|Host) ?
- [ ] Reorganize / cleanup
