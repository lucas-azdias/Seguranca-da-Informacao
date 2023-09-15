import socket
import RSALib as RSA
import AESLib as AES

size_assimetrica = 2048

file_chave_privada = "chave_privada.pem"
file_chave_publica = "chave_publica.pem"

# 1) ALICE GERA AS CHAVES PÚBLICAS E PRIVADA
chavePrvObj, chavePrvPEM = RSA.geraChavePrivada(size_assimetrica, file_chave_privada)
chavePubObj, chavePubPEM = RSA.geraChavePublica(chavePrvObj, file_chave_publica)

print('ESTA TELA PERTENCE A ALICE')

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('', 9999))

while True:
    
    data, addr = s.recvfrom(1024) 
    datastr = data.decode()   
    print(f'RECEBI {datastr} de {addr}')

    if datastr == "HELLO":
        # 2) ALICE TRANSMITE SUA CHAVE PÙBLICA 
        # -- troque string CHAVE PUBLICA pela chave publica em formato base64 (e remova o encode)
        s.sendto(chavePubPEM, addr)

        # 3) ALICE RECEBE A CHAVE SECRETA DE BOB (em formato PEM) criptografada
        chaveCifrada, addr = s.recvfrom(1024)
        print(f'RECEBI uma chave cifrada de {addr}')

        # 4) ALICE DESCRIPTOGRAFA A chave secreta e converte para binário
        # observe que a chave não é texto, por isso use a opção text=False
        chaveSecreta = RSA.decifraComPrivada(chaveCifrada, chavePrvObj, text=False)

        # 5) ALICE criptografa uma mensagem para BOM usando essa chave
        mensagem = 'OLA! Voce criou um canal criptografado com a ALICE.'
        cipher_mensagem = AES.cifraMensagem(mensagem, chaveSecreta)

        # 6) ALICE envia a mensagem cifrada para BOB
        # -- troque a string MENSAGEM CIFRADA pela variavel com a mensagem criptografada em base64 (e remova o encode)
        s.sendto(cipher_mensagem, addr)       
   
    else: 
        print('descartei uma mensagem de ', addr)




