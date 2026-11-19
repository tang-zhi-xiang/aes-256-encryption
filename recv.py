import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 5000))
server.listen()
connection, address = server.accept()
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,X25519PublicKey,)
from cryptography.hazmat.primitives.serialization import (Encoding,PublicFormat,)
bpriv=X25519PrivateKey.generate()
bpublic=bpriv.public_key()
bpublicbytes=bpublic.public_bytes(encoding=Encoding.Raw,format=PublicFormat.Raw)
connection.sendall(bpublicbytes)
apublicbytes=connection.recv(32)
apublic=X25519PublicKey.from_public_bytes(apublicbytes)
shared_secret=bpriv.exchange(apublic)
key=HKDF(algorithm=hashes.SHA256(),length=32,salt=None).derive(shared_secret)
aesgcm=AESGCM(key)
while True:
    p=b""
    length=connection.recv(4)
    if not length:
        break
    else:
        length = int.from_bytes(length, "big")
    while length>0:   
        packet=connection.recv(min(4096, length))
        p+=packet
        length-=len(packet)
    try:
        nonce=p[:12]
        encrypted=p[12:]
        decrypted=aesgcm.decrypt(nonce,encrypted,None)
        decrypted_msg = decrypted.decode('utf-8')
        if decrypted_msg == "EXIT":
            break
        print(f"Received: '{decrypted_msg}' from Computer A")
    except Exception as e:
        print("Decryption failed(tampering or wrong key)")
