from Crypto.Cipher import AES
import base64

MASTER_KEY = '12345678901234567890123456789012'

def encrypt(data):
  secret = AES.new(MASTER_KEY)
  tagString = str(data) + (AES.block_size - len(str(data)) % AES.block_size) * "\0"
  cipherText = base64.b64encode(secret.encrypt(tagString))
  return cipherText

def decrypt(encryptedData):
  secret = AES.new(MASTER_KEY)
  rawDecrypted = secret.decrypt(base64.b64decode(encryptedData))
  data = rawDecrypted.rstrip("\0")
  return data