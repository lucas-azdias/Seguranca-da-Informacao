import socket
import ssl

host_addr = 'netiswork.pro.br'
host_port = 40232
peer_name = 'netiswork.pro.br'
peer_cert = 'certCA.pem'
my_cert = 'client.pem'
my_key = 'client.key'


def prepara_contexto():
    contexto = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    contexto.verify_mode = ssl.CERT_REQUIRED
    contexto.load_cert_chain(certfile=my_cert, keyfile=my_key)
    contexto.load_verify_locations(cafile=peer_cert)
    contexto.check_hostname = True
    return contexto


def verifica_conexao(ssock):
    print('ciphers negociados: ')
    for c in ssock.shared_ciphers(): print(c)
    print('cipher selecionado: ', ssock.cipher())

    cert = ssock.getpeercert()
    # print(contexto.cert_store_stats())
    # for k,v in cert.items(): print(f'{k}={v}')
    for i in cert['subject']: 
        if i[0][0] == 'commonName': identidade = i[0][1]
    for i in cert['issuer']: 
        if i[0][0] == 'commonName': print('Certificado por', i[0][1])
    
    return identidade


def faz_conexao(s, contexto):
    try:
        ssock = contexto.wrap_socket(s, server_side=False, server_hostname=peer_name)
        ssock.connect((host_addr, host_port))
        sid = verifica_conexao(ssock)

        return ssock, sid

    except Exception as e:
        print(e)
        return None, 'LIAR!!!'


if __name__ == "__main__":

    contexto = prepara_contexto() 

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        ssock, sid = faz_conexao(s, contexto)
        if ssock is None: exit()           
        
        print(f'Conectado em {sid}')

        while True:
            msg = input('mensagem: (ou <ENTER> para encerrar): ')
            if not msg: break
            ssock.send(msg.encode())

        ssock.close()
