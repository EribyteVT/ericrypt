from quart import Quart, request
from EncryptDecrypt import EncryptDecrypt
import base64
import os


from quart import Quart

app = Quart(__name__)

encryptService = EncryptDecrypt(os.environ.get("ENCRYPTION_KEY"))
endpointPassword = os.environ.get("ENDPOINT_PASSWORD")


@app.route('/')
async def hello():
    return 'hello'

@app.route('/encrypt', methods=["POST"])
async def encrypt():
    data = await request.get_json()
    encrypted, salt = encryptService.encrypt(data["to_encrypt"])
    return {"encrypted":encrypted.decode('utf-8') , "salt":base64.b64encode(salt).decode('utf-8')}

@app.route('/decrypt', methods=["POST"])
async def decrypt():
    data = await request.get_json()

    if(data["password"] != endpointPassword):
        print("INCORRECT PASSWORD")
        return "FORBIDDEN"

    to_decrypt = data["encrypted"]
    salt = data["salt"]
    salt = base64.b64decode(salt.encode("utf-8"))
    decrypted = encryptService.decrypt(to_decrypt,salt)


    return {"decrypted":decrypted}

app.run()