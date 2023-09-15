import socket
import MyHashLib as HL


# O computador de BOB foi comprometido através de um ataque do tipo Watering Hole
# CHARLES induziu BOB a instalar um programa com malware que intercepta os pacotes enviados para rede e envia uma cópia para CHARLES
# Crie uma estratégia para que BOB consiga se logar em ALICE.
# A solução deve ser imune a ataques de REPETIÇÃO (REPLAY)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ALICE = ('127.0.0.1', 9999)

SEQS = list()  # seqs de mensagens recebidas


while True:

    login = input('digite seu LOGIN: ')
    senha = input('digite sua SENHA: ')


# 1) BOB ENVIA UM HELLO PARA ALICE
    msg = HL.formataMensagem(['HELLO', login])
    s.sendto(msg, ALICE)
    s.sendto(msg, HL.CHARLES)  # essa linha simula a ação do MALWARE


# 2) BOB RECEBE UM CHALLENGE
    data, addr = s.recvfrom(1024)
    print('RECEBI: ', data)

    msg = HL.separaMensagem(data)
    if len(msg) < 3 or msg[0] != "CHALLENGE":
        print('recebi uma mensagem inválida')
        continue

# 3) BOB responde ao CHALLENGE com um novo CHALLENGE e o HASH da sua senha
# -- troque string NONCE por um nonce em formato base64 convertido para string (decode)
# -- troque o HASH_SENHA pelo HASH da senha com o challenge da ALICE (string)

    _, cs_BOB = HL.geraNonce(128)

    cs_ALICE = msg[1]
    salt = msg[2]

    _, senha_HASH = HL.calculaHASH(senha + salt)
    _, local_HASH = HL.calculaHASH(senha_HASH + cs_ALICE)
    data = HL.formataMensagem(
        ['CHALLENGE_RESPONSE', cs_BOB.decode(), local_HASH])

    s.sendto(data, addr)
    s.sendto(data, HL.CHARLES)  # essa linha simula a ação do MALWARE


# 4) BOB recebe o resultado da autenticaçao
# -- e verifica se ALICE é o servidor verdadeiro
    data, addr = s.recvfrom(1024)
    print('RECEBI: ', data)
    msg = HL.separaMensagem(data)
    resultado = msg[0]
    prova = msg[1]

    _, local_HASH = HL.calculaHASH(senha_HASH + cs_BOB.decode())


# 5) BOB se a senha está correta
    if resultado == 'SUCCESS' and local_HASH == prova:
        print('Este servidor é ALICE')
    else:
        print('Este servidor não é ALICE')


# 6) BOB recebe uma mensagem autenticada de ALICE

    while True:
        print('Aguardando mensagens do Servidor')
        data, addr = s.recvfrom(1024)
        print('RECEBI: ', data)

        msg = HL.separaMensagem(data)

        if msg[-1] in SEQS:
            print('ATAQUE DETECTADO: mensagem duplicada')
            continue

        if msg[0] == 'HMAC':
            resultado = HL.verificaMensagem(data, senha_HASH)
            if resultado:
                SEQS.append(msg[-1])
                print(msg[1])
                continue

        print('recebi uma mensgem inválida')
