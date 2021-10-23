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

## Dependencies and References

1. [Django][django-home]
2. [JWT][jwt-reference]
3. [JWT RFC7519][jwt-rfc]
4. [Authlib][authlib-home]
5. [Django CORS][django-cors-headers]
6. [Python Cryptography][python-cryptography]
7. [Python LDAP][python-ldap]


[django-home]: https://www.djangoproject.com/
[jwt-reference]: https://jwt.io/
[jwt-rfc]: https://datatracker.ietf.org/doc/html/rfc7519
[authlib-home]: https://docs.authlib.org/en/latest/
[django-cors-headers]: https://github.com/adamchainz/django-cors-headers
[python-cryptography]: https://cryptography.io/en/latest/
[python-ldap]: https://www.python-ldap.org/en/python-ldap-3.3.0/index.html
