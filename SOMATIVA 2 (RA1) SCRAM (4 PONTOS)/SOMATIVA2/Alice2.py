import socket
import MyHashLib as HL


# O servidor ALICE foi comprometido através de um ataque do tipo Watering Hole
# CHARLES induziu a ALICE a instalar um programa com malware que intercepta os pacotes enviados para rede e envia uma cópia para CHARLES
# Crie uma estratégia para que ALICE receba a autenticação de usuários pela rede.
# A solução deve ser imune a ataques de REPETIÇÃO (REPLAY)


# ALICE tem uma base de senhas cadastradas

# senhas = {
#     'BOB': 'SEGREDO',
#     'MOE': 'SENHA',
#     'LARRY': 'OPA',
#     'CURLY': 'YAHOO'
# }

senhas = {  # user: (senha_HASH, salt)
    # salt deveria ser em base64 e grande
    'BOB': ('9aa575726546f2861e2e94c9a90c97cc', b'827ccb0eea8a706c4c34a16891f84e7b'),
    'MOE': ('2ab2cda458b9cc3fa4ffaef45537752b', b'01cfcd4f6b8770febfb40cb906715822'),
    'LARRY': ('e02439864949812ec6ba1991a424a939', b'd3eb9a9233e52948740d7eb8c3062d14'),
    'CURLY': ('def953931b993f9fb2332022fbb4c5e8', b'dcddb75469b4b4875094e14561e573d8')
}


print('ESTA TELA PERTENCE A ALICE')

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('', 9999))

while True:

    # 1) ALICE AGUARDA UM PEDIDO DE LOGIN

    print('Aguardando solicitação de LOGIN ...')

    data, addr = s.recvfrom(1024)
    print('RECEBI: ', data)
    msg = HL.separaMensagem(data)

    if len(msg) < 2 or msg[0] != 'HELLO':
        print('recebi uma mensagem inválida')
        continue
    else:
        user = msg[1]
        user_addr = addr
        if user not in senhas.keys():
            print('Usuario desconhecido')
            continue


# 2) ALICE responde ao HELLO com um CHALLENGE
# -- troque string NONCE por um nonce em formato base64 convertido para string (decode)

    _, cs_ALICE = HL.geraNonce(128)
    data = HL.formataMensagem(
        ['CHALLENGE', cs_ALICE.decode(), senhas[user][1].decode()])

    s.sendto(data, addr)
    if addr != HL.CHARLES:
        s.sendto(data, HL.CHARLES)  # essa linha simula a ação do MALWARE


# 3) ALICE recebe a resposta do CHALLENGE
# -- é preciso separar os componentes da mensagem

    data, addr = s.recvfrom(1024)
    print('RECEBI: ', data)

    if addr != user_addr:
        print('mensagem de origem desconhecida')
        continue

    msg = HL.separaMensagem(data)

    if len(msg) < 3 or msg[0] != 'CHALLENGE_RESPONSE':
        print('recebi uma mensagem inválida')
        continue
    else:
        cs_BOB = msg[1]
        hash_BOB = msg[2]


# 4) ALICE verifica se a senha está correta
# -- e preciso calcular o local_HASH usando a CHALLENGE da Alice
# -- faça a comparação com o HASH da senha com o CHALLENGE

    _, local_HASH = HL.calculaHASH(senhas[user][0] + cs_ALICE.decode())

    if hash_BOB == local_HASH:
        resposta = 'SUCCESS'
        print(f'Este usuário é {user}')
    else:
        resposta = 'FAIL'
        print(f'Ataque detectado: Pedido de LOGIN NEGADO!!!')
        continue    # ATENCAO: remova essa linha para fazer o teste de repetição do HMAC

# -- substitua hash_string pelo hash calculado com a senha e o challenge enviado por BOB

    _, local_HASH = HL.calculaHASH(senhas[user][0] + cs_BOB)

    msg = HL.formataMensagem([resposta, local_HASH])

    s.sendto(msg, addr)
    if addr != HL.CHARLES:
        s.sendto(msg, HL.CHARLES)  # essa linha simula a ação do MALWARE


# 5) ALICE envia uma mensagem assinada para BOB

    data = HL.assinaMensagem(
        f'OLA USUARIO {user} VOCE ESTA AUTENTICADO NA ALICE!', senhas[user][0])

    s.sendto(data, addr)
    if addr != HL.CHARLES:
        s.sendto(data, HL.CHARLES)  # essa linha simula a ação do MALWARE
