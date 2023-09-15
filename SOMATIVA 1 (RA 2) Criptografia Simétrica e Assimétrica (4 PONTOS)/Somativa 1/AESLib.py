
# Ver https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import os

# Cripografa com AES, assume que plaintext é uma string
def cifraMensagem(plaintext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB())     
    cifrador = cipher.encryptor()
    plainbytes = plaintext.encode()
    
    padder = padding.PKCS7(128).padder()
    plainbytes = padder.update(plainbytes) + padder.finalize()
    
    cipherbytes = cifrador.update(plainbytes) + cifrador.finalize()
    ciphertext = b64encode(cipherbytes)   
    return ciphertext

# Cripografa com AES, assume que ciphertext é uma base64 (bytes)
def decifraMensagem(ciphertext, key):    
    cipher = Cipher(algorithms.AES(key), modes.ECB()) 
    decifrador = cipher.decryptor()
    cipherbytes = b64decode(ciphertext)

    plainbytes = decifrador.update(cipherbytes) + decifrador.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plainbytes = unpadder.update(plainbytes) + unpadder.finalize()

    plaintext = plainbytes.decode()
    return plaintext

# Gera chave simétrica
def geraChave(tamanho):
    embytes = int(tamanho/8)
    chave = os.urandom(embytes)
    chavePEM = b64encode(chave)
    return chave, chavePEM


# Use essa porção do código para testar as funções da biblioteca

if __name__ == "__main__":
   
    chavesecreta, chavePEM = geraChave(128)

    plaintext = 'isto é um teste de qualquer tamanho'
    ciphertext = cifraMensagem(plaintext, chavesecreta)
    print(ciphertext)
    plaintext2 = decifraMensagem(ciphertext, chavesecreta)
    print(plaintext2)