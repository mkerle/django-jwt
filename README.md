# django-jwt
Django Python example backend to authenticate user with LDAP and return a JWT.

## Installation

Assumes that `python` is python3.

1. `$ pipenv install django`
2. `$ pipenv shell`
3. `$ pip install Authlib`
4. `$ pip install django-cors-headers`
5. `$ pip install cryptography`
6. `$ pip install python-ldap`
7. `$ git clone https://github.com/mkerle/django-jwt`
8. `$ python manage.py runserver 9000`

## Configuration

Update variables in jwtauth/views.py

LDAP variables:
- `LDAP_SERVER_IP` - IP address of LDAP/Active Directory Domain Controller
- `LDAP_SERVER_PORT` - Port that LDAP server is listening on.
- `LDAP_TLS_ENABLE` - Enable TLS connection to LDAP server.
- `LDAP_TLS_CERT_PATH` - Certificate to be used for TLS communication to LDAP server.
- `LDAP_BASE_DN` - Base DN to search for users when authenticating.

JWT variables:
- `JWT_ISSUER` - Issuer of the JWT token (hostname of the server/app).
- `JWT_DEFAULT_EXPIRY` - Expiry time in seconds of the JWT token
- `JWT_PRIVATE_KEY_PATH` - Path to private key to encrypt/sign the JWT.
- `JWT_PRIVATE_KEY_PASSWORD` - Password on the private key.  This should be obfuscated or stored in a keystore for production environments.
- `JWT_PUBLIC_KEY_PATH` - Public key that be used to validate a JWT.

## Dependencies and References

1. [Django][django-home]
2. [JWT][jwt-reference]
3. [JWT RFC7519][jwt-rfc]
4. [Authlib][authlib-home]
5. [Django CORS][django-cors-headers]
6. [Python Cryptography][python-cryptography]
7. [Python LDAP][python-ldap]

## Future Work and Improvements

1. Add TLS support to LDAP
2. Add endpoint to request public key for JWT validation on clients
3. Move LDAP authentication code to its own module


[django-home]: https://www.djangoproject.com/
[jwt-reference]: https://jwt.io/
[jwt-rfc]: https://datatracker.ietf.org/doc/html/rfc7519
[authlib-home]: https://docs.authlib.org/en/latest/
[django-cors-headers]: https://github.com/adamchainz/django-cors-headers
[python-cryptography]: https://cryptography.io/en/latest/
[python-ldap]: https://www.python-ldap.org/en/python-ldap-3.3.0/index.html
