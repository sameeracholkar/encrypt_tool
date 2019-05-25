from Crypto.Cipher import AES
import base64
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
password = config.get('configuration', 'password')

msg_text = '{}'.format(password).rjust(32)
secret_key = '1234567890123456' # create new & store somewhere safe

cipher = AES.new(secret_key,AES.MODE_ECB) # never use ECB in strong systems obviously
encoded = base64.b64encode(cipher.encrypt(msg_text))
decoded = cipher.decrypt(base64.b64decode(encoded))
encoded = str(encoded)
encoded = encoded.replace("b'", "")
encoded = encoded.replace("'", "")
print(encoded.strip())
