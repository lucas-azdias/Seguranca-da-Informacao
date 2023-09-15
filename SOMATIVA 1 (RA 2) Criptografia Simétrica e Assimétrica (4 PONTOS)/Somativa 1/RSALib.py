# ver RSA: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/


from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
from base64 import b64encode, b64decode

# Gera a chave privada e salva (opcionalmente) em um arquivo
def geraChavePrivada(tamanho, arquivo=None):

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=tamanho,
    )

    if arquivo is not None:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
            )
        with open(arquivo, "wb") as key_file:
            key_file.write(private_pem)
        
    return private_key, private_pem

# Calcula a chave pública a partir da chave privada e salva (opcionalmente) em um arquivo
def geraChavePublica(private_key, arquivo=None):
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    if arquivo is not None:
        with open(arquivo, "wb") as key_file:
            key_file.write(public_pem)

    return public_key, public_pem

# Carrega a chave privada de um arquivo (a chave não deve ser gerada a cada vez que o algoritmo é executado) 
def carregaChavePrivada(arquivo):
    with open(arquivo, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
    return private_key

# A chave pública vem pela rede em formato PEM, então é necessário convertê-la antes de usá-la
def converteChavePublica(public_pem):
    public_key = serialization.load_pem_public_key(public_pem)
    return public_key

# Cifra com a chave pública. Por default, plaintext é uma string (use text=False para bytes)
def cifraComPublica(plaintext, public_key, text=True):

    plainbytes = plaintext.encode() if text else plaintext
    
    cipherbytes = public_key.encrypt(
        plainbytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    ciphertext = b64encode(cipherbytes)

    return ciphertext

# Decifra com a chave privada. Considere que ciphertext é uma base64 em bytes
def decifraComPrivada(ciphertext, private_key, text=True):

    cipherbytes = b64decode(ciphertext)
    plainbytes = private_key.decrypt(
        cipherbytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


    plaintext = plainbytes.decode() if text else plainbytes

    return plaintext


# Use essa porção do código para testar as funções da biblioteca

if __name__ == "__main__":

    # As chaves serão salvas nesta pasta
    print("Diretorio:", os.getcwd(), '\n')

    # Obj são estruturas usadas pelo algoritmo em Python, PEM são chaves transportáveis (serializadas) em formato base64
    # Observe que o formato PEM é um formato padrão independente da linguagem, mas Obj é um formato do Python
    chavePriObj, chavePriPEM = geraChavePrivada(2048, "chavepriva.pem")
    chavePubObj, chavePubPEM = geraChavePublica(chavePriObj, "chavepublica.pem")

    print(chavePriPEM.decode(), '\n' )
    print(chavePubPEM.decode(), '\n')      

    # A chave publica virá pela rede pelo formato PEM, então é necessário convertê-la antes de usar
    chavePubObj2 = converteChavePublica(chavePubPEM)

    # Criptografa com a chave pública (o resultado é base64)
    ciphertext = cifraComPublica('YAHOO, deu certo!!!', chavePubObj2 )

    print('MENSAGEM CIFRADA')
    print(ciphertext.decode(), '\n')

    # Descriptografa com a chave privada (o resultado é texto)
    plaintext = decifraComPrivada(ciphertext, chavePriObj)
    
    print('MENSAGEM DECIFRADA')
    print(plaintext)

 






