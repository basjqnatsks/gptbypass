import os
import base64
import hashlib
from cryptography.fernet import Fernet

PASSWORD = "pass"
EXTENSION = ".txt"


sha_key = hashlib.sha256(PASSWORD.encode()).digest()
fernet_key = base64.urlsafe_b64encode(sha_key)
cipher = Fernet(fernet_key)
for filename in os.listdir("."):
	if filename.endswith(EXTENSION):
		with open(filename, "rb") as f:
			plaintext = f.read()
		ciphertext = cipher.encrypt(plaintext)
		enc_filename = filename + ".enc"
		with open(enc_filename, "wb") as f:
			f.write(ciphertext)