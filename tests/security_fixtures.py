"""Independent signed-context and TLS material, used only in owned native-engine tests."""
import base64
import datetime as dt
import hashlib
import ipaddress
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
from cryptography.x509.oid import NameOID


def create(directory):
    trusted = ec.generate_private_key(ec.SECP256R1())
    attacker = ec.generate_private_key(ec.SECP256R1())
    def pin(key):
        return base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,
                               serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    def sign(prefix, payload, bad=False):
        def b64(data):
            return base64.urlsafe_b64encode(data).decode().rstrip('=')
        body = b64(json.dumps(payload, separators=(',', ':')).encode())
        r, s = utils.decode_dss_signature((attacker if bad else trusted).sign(body.encode(), ec.ECDSA(hashes.SHA256())))
        return prefix + '.' + body + '.' + b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))
    proof = {'version': 1, 'licenseKeySha256': hashlib.sha256(b'PERMIT-TEST-VECT-0R00-0001').hexdigest(),
             'productId': '44444444-4444-4444-4444-444444444444', 'deviceId': 'test-device-001',
             'deviceActivated': True, 'nodeLocked': True, 'isValid': True,
             'features': ['pro', 'export'], 'productName': 'Fictional Godot tool',
             'validUntil': '2099-01-01T00:00:00Z'}
    cases = [{'name': 'valid', 'token': sign('pc_grace_v1', proof), 'validate': True, 'activate': True}]
    for field, value in [('licenseKeySha256', 'wrong'), ('licenseKeySha256', None), ('productId', None),
                         ('productId', 'other'), ('deviceId', 'other'), ('deviceId', None),
                         ('validUntil', 'bad'), ('validUntil', '2020-01-01T00:00:00Z'),
                         ('isValid', False), ('isValid', 'true'), ('deviceActivated', False)]:
        p = dict(proof); p[field] = value
        cases.append({'name': field + '-' + str(value), 'token': sign('pc_grace_v1', p), 'validate': False, 'activate': False})
    p = dict(proof); p.update(nodeLocked=False, deviceId=None, deviceActivated=False)
    cases.append({'name': 'unbound-validation-only', 'token': sign('pc_grace_v1', p), 'validate': True, 'activate': False})
    cases.append({'name': 'attacker-key-in-cache', 'token': sign('pc_grace_v1', proof, True), 'publicKey': pin(attacker), 'validate': False, 'activate': False})
    result = {'pin': pin(trusted), 'attackerPin': pin(attacker), 'graceCases': cases,
              'manual': sign('pc_offline_v1', {'version': 1, 'deviceId': 'test-device-001',
                      'productId': proof['productId'], 'expiresAt': '2099-01-01T00:00:00Z'}),
              'validGrace': cases[0]['token']}
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'PermitCore owned Godot test CA')])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
          .not_valid_after(now + dt.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]))
            .issuer_name(name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
            .sign(ca_key, hashes.SHA256()))
    wrong_leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'wrong.invalid')]))
                  .issuer_name(name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
                  .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
                  .add_extension(x509.SubjectAlternativeName([x509.DNSName('wrong.invalid')]), False)
                  .sign(ca_key, hashes.SHA256()))
    for file, content in [('ca.pem', ca.public_bytes(serialization.Encoding.PEM)),
                          ('leaf.pem', leaf.public_bytes(serialization.Encoding.PEM)),
                          ('wrong-leaf.pem', wrong_leaf.public_bytes(serialization.Encoding.PEM)),
                          ('leaf.key', leaf_key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))]:
        path = directory / file; path.write_bytes(content); path.chmod(0o600)
    result['caFile'] = str(directory / 'ca.pem')
    return result
