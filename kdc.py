"""Trusted KDC for simplified five-message symmetric key protocol."""
import argparse
import secrets
import socket
import threading
from protocol import receive, send, seal, read_key

ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'


def handle(conn, address, keys):
    request = receive(conn)
    if request.get('type') != 'request' or request.get('from') != 'alice' or request.get('to') != 'bob':
        raise ValueError('Invalid identities/request')
    nonce = request['n1']
    if not isinstance(nonce, str) or len(nonce) > 128:
        raise ValueError('Bad nonce')
    print(f'\n(1) Request dari {address}: alice || bob || N1={nonce}')
    ks = ''.join(secrets.choice(ALPHABET) for _ in range(16))
    alice_box = seal({'ks': ks, 'alice': 'alice', 'bob': 'bob', 'n1': nonce}, keys['ka'])
    ticket = seal({'ks': ks, 'alice': 'alice'}, keys['kb'])
    send(conn, {'type': 'kdc_reply', 'for_alice': alice_box, 'ticket': ticket})
    print('(2) E(Ka, [Ks||IDA||IDB||N1]):', alice_box['ciphertext'])
    print('    E(Kb, [Ks||IDA])         :', ticket['ciphertext'])


def serve(server, keys):
    while True:
        conn, address = server.accept()
        with conn:
            try:
                handle(conn, address, keys)
            except Exception as e:
                print('\nRejected request:', e)
                try:
                    send(conn, {'type': 'error', 'message': 'KDC request failed'})
                except OSError:
                    pass
        print('KDC > ', end='', flush=True)


def run(host, port):
    keys = {'ka': read_key('Ka (Alice-KDC)'), 'kb': read_key('Kb (Bob-KDC)')}
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen()
    threading.Thread(target=serve, args=(server, keys), daemon=True).start()
    print('KDC listening on', host, port)
    print('Perintah: /ka ganti Ka, /kb ganti Kb, /quit keluar')
    while True:
        command = input('KDC > ').strip()
        if command == '/ka':
            keys['ka'] = read_key('Ka baru')
            print('Ka diganti.')
        elif command == '/kb':
            keys['kb'] = read_key('Kb baru')
            print('Kb diganti.')
        elif command == '/quit':
            break
    server.close()


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--host', default='0.0.0.0')
    p.add_argument('--port', type=int, default=5001)
    a = p.parse_args()
    run(a.host, a.port)
