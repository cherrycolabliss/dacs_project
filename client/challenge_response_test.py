import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

'''
This python is file is only for testing the challenge and response logic for server.py for phase 4
So dont worry about it that much lol.

Might move the test_connection function elsewhere and use it as an extra "visual check" so the user
can see that the server is on,. If we're doing web implementation feel free to use it.
'''


# For testing the server
def test_connection():
    response = requests.get("http://127.0.0.1:5000/test")
    print("Server says:", response.json())

# Generate keypair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

# Serialize keys
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print(private_pem.decode())
print(public_pem.decode())
