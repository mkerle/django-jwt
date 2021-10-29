from django.shortcuts import render
from django.http import HttpResponse
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.csrf import csrf_exempt
import json
from authlib.jose import jwt
from cryptography.hazmat.primitives import serialization
import datetime
import ldap

LDAP_SERVER_IP = '10.1.1.250'
LDAP_SERVER_PORT = '389'
LDAP_TLS_ENABLE = False
LDAP_TLS_CERT_PATH = 'jwtauth/ad-pub.crt'
LDAP_BASE_DN = 'cn=users,dc=mitch,dc=local'
LDAP_BIND_DN = 'svc_ldap_bind_acc'
LDAP_BIND_PASSWORD = 'Password1'

JWT_ISSUER = 'jwt.mitch.local'
JWT_DEFAULT_EXPIRY = 60     # seconds
JWT_PRIVATE_KEY_PATH = 'jwtauth/key.pem'
JWT_PRIVATE_KEY_PASSWORD = 'Password1'      # retrieve from keyring or at least obfuscate
JWT_PUBLIC_KEY_PATH = 'jwtauth/mypubkey.pem'

def getPublicKey(request):

    pubKey = getJWTPublicKey(JWT_PUBLIC_KEY_PATH).public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return JsonResponse({'publicKeyBytes' : pubKey.decode('utf-8')})

def getJWTPublicKey(jwtPublicKeyPath):
    with open(jwtPublicKeyPath, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )

    return public_key


@ensure_csrf_cookie
def login(request):

    if (request.method == 'POST'):

        data = json.loads(request.body)
        if ('username' in data and 'password' in data):

            ldapResult = ldapSearchUser(data['username'], data['password'])
            if (ldapAuthenticate(ldapResult)):

                groups = []
                for group in ldapResult[0][1].get('memberOf'):
                    groups.append(group.decode('utf-8'))

                principalName = ldapResult[0][1].get('userPrincipalName')[0].decode('utf-8')
                name = ldapResult[0][1].get('name')[0].decode('utf-8')

                exp = generateJWTExpiryTime(JWT_DEFAULT_EXPIRY)
                payload = {
                    'iss': JWT_ISSUER, 
                    'sub': principalName, 
                    'exp' : exp, 
                    'name' : name, 
                    'groups' : groups  
                }
                header = {'alg': 'RS256'}

                s = jwt.encode(header, payload, getJWTPrivateKey(JWT_PRIVATE_KEY_PATH, JWT_PRIVATE_KEY_PASSWORD))

                return JsonResponse({ 'token' : s.decode('utf-8') })
            
            
        return JsonResponse({ })


    else:

        return HttpResponse('')

def generateJWTExpiryTime(tokenExpirySecs):

    return int((datetime.datetime.now()+datetime.timedelta(seconds=tokenExpirySecs)).timestamp())

def getJWTPrivateKey(jwtPrivateKeyPath, jwtPrivateKeyPassword):
    with open(jwtPrivateKeyPath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=bytes(jwtPrivateKeyPassword, 'utf-8'),
        )

    return private_key


def ldapAuthenticate(ldapSearchResult):

    if (ldapSearchResult is not None):
        if (len(ldapSearchResult) == 1):
            if (ldapSearchResult[0][1]):
                return True

    return False

def getUserDN(userData):

    dn = ''
    if (userData and len(userData) == 1 and userData[0][1] and 'distinguishedName' in userData[0][1]):
        return userData[0][1]['distinguishedName'][0].decode('utf-8')

def ldapSearchUser(user, password):

    try:
        constr = 'ldap://' + LDAP_SERVER_IP + ':' + LDAP_SERVER_PORT
        if (LDAP_TLS_ENABLE):
            constr = 'ldaps://' + LDAP_SERVER_IP + ':' + LDAP_SERVER_PORT

        con = ldap.initialize(constr, bytes_mode=False)

        if (LDAP_TLS_ENABLE):        
            con.set_option(ldap.OPT_X_TLS_CACERTFILE, LDAP_TLS_CERT_PATH)
            con.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
            con.start_tls_s()

        con.simple_bind_s(LDAP_BIND_DN, LDAP_BIND_PASSWORD)

        userLDAPData = con.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, u'(sAMAccountName=' + user + ')')
        con.unbind_s()

        # bind using user DN and password - if wrong will throw exception
        userDN = getUserDN(userLDAPData)
        con = ldap.initialize(constr, bytes_mode=False)
        con.simple_bind_s(userDN, password)

        return userLDAPData
    except:
        return None