import os
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (X25519PrivateKey,X25519PublicKey,)
from cryptography.hazmat.primitives.serialization import (Encoding,PublicFormat,)
client=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip=input("Enter receiver IP address: ")
client.connect((ip, 5000))
apriv=X25519PrivateKey.generate()
apublic=apriv.public_key()
apublicbytes=apublic.public_bytes(encoding=Encoding.Raw,format=PublicFormat.Raw)
client.sendall(apublicbytes)
bpublicbytes=client.recv(32)
bpublic=X25519PublicKey.from_public_bytes(bpublicbytes)
shared_secret=apriv.exchange(bpublic)
key=HKDF(algorithm=hashes.SHA256(),length=32,salt=None).derive(shared_secret)
aesgcm=AESGCM(key)
print("Type EXIT to exit the code")
while True:
  msg=input("")
  byte=msg.encode('utf-8')
  nonce=os.urandom(12)
  encrypted=aesgcm.encrypt(nonce,byte,None)
  packet=nonce+encrypted
  length=len(packet).to_bytes(4, "big")
  client.sendall(length)
  if msg!="EXIT":
    print(f"Sent: '{msg}' to Computer B")
  client.sendall(packet)
  if msg=="EXIT":
    break
