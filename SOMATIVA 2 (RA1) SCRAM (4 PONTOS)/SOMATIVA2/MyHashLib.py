# ESSA BIBLIOTECA É USADA PARA DEMONSTRAR O MECANISMO SCRAM
# SCRAM: SALTED CHALLENGE RESPONSE MECHANISM

import hashlib
import hmac
import os
from base64 import b64encode, b64decode

CHARLES = ('127.0.0.1', 8888)

SEQ = 0  # contador de mensagens trocadas


# msg é uma string
# retorna o hash em bytes e como hexadecimal em formato de string
def calculaHASH(msg):
    m = hashlib.md5()
    m.update(msg.encode())
    return m.digest(), m.hexdigest()


# tamanho é um número inteiro (bits)
# retorna o nonce em bytes e como bytes em base64
def geraNonce(tamanho):
    embytes = int(tamanho/8)
    nonce = os.urandom(embytes)
    nonceB64 = b64encode(nonce)
    return nonce, nonceB64


# separa os componentes da mensagem (em bytes) usado \n como separador (default)
# retorna uma lista com os componentes
def separaMensagem(mensagem, separador='\n'):
    msg = mensagem.decode()
    return msg.split(separador)


# junta os componentes da mensagem usado \n como separador (default)
# componentes são uma lista de strings
# retorna a mensagem como bytes para ser transmitida pela rede
def formataMensagem(componentes, separador='\n'):
    mensagem = separador.join(componentes)
    return mensagem.encode()


# gera uma mensagem assinada usando HMAC
# mensagem e segredo são strings
# retorna uma mensagem codificada em bytes para ser enviada pela rede
def assinaMensagem(mensagem, segredo):
    global SEQ
    SEQ += 1
    meuHMAC = hmac.HMAC((segredo + str(SEQ)).encode(),
                        mensagem.encode(), hashlib.md5)
    digest = meuHMAC.hexdigest()  # esse resultado e uma string
    return formataMensagem(['HMAC', mensagem, digest, str(SEQ)])


# verifica uma mensagem assinada com HMAC
# assume que data são bytes (recebidos pela rede)
def verificaMensagem(data, segredo):
    tipo, mensagem, digest, seq = separaMensagem(data)
    if tipo != 'HMAC':
        raise Exception('MENSAGEM INVÁLIDA')

    meuHMAC = hmac.HMAC((segredo + seq).encode(),
                        mensagem.encode(), hashlib.md5)
    localdigest = meuHMAC.hexdigest()

    if digest == localdigest:
        print('mensagem válida')
        return True
    else:
        print('mensagem invalida')
        return False


# Use essa porção do código para testar as funções da biblioteca

if __name__ == "__main__":

    hash, strhash = calculaHASH('segredo')
    cs, cs64 = geraNonce(128)

    hash_bytes, hash_string = calculaHASH('segredo' + cs64.decode())
    print(hash_string)

    print(formataMensagem(['HELLO', 'BOB']))

    print(separaMensagem(b'HELLO\nBOB'))

    msgassinada = assinaMensagem('teste', 'segredo')

    print(verificaMensagem(msgassinada, 'segredo'))
