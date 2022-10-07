from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

#generation of the keys
def generate_keys():
    #generating private key
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    #generating public key from private key
    public = private.public_key()
    return private,public


#signing the message
def sign(message,private):
    #converting message to bytes
    message = bytes(str(message),'utf-8')
    signature = private.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

#verification function
def verify(message,signature,public):
    message = bytes(str(message), 'utf-8')
    try:
        public.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except:
        print('Error Executing try block')
        return False

if __name__ == '__main__':
    pr,pu=generate_keys()
    # print(pr)
    # print(pu)
    message = 'I am Kanika'
    sig = sign(message,pr)
    # print(sig)
    correct = verify(message,sig,pu)
    if correct:
        print('Successful')
    else:
        print('Failed')