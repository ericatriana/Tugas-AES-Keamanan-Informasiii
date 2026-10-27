"""Bob TCP server; background thread accepts Alice while main thread sends chat."""
import argparse
import secrets
import socket
import threading
from protocol import receive, send, open_seal, seal, read_key


def handshake(conn, kb):
    packet = receive(conn)
    if packet.get('type') != 'ticket':
        raise ValueError('Expected ticket')
    print('(3) Ticket E(Kb, ...):', packet['ticket']['ciphertext'])
    ticket = open_seal(packet['ticket'], kb)
    if ticket.get('alice') != 'alice':
        raise ValueError('Wrong identity')
    ks = ticket['ks'].encode('ascii')
    if len(ks) != 16:
        raise ValueError('Bad Ks')
    n2 = secrets.token_hex(16)
    box = seal({'n2': n2}, ks)
    send(conn, {'type': 'challenge', 'box': box})
    print('(4) Challenge E(Ks, N2):', box['ciphertext'])
    reply = receive(conn)
    if reply.get('type') != 'challenge_response':
        raise ValueError('Wrong response')
    print('(5) Jawaban E(Ks, f(N2)):', reply['box']['ciphertext'])
    answer = open_seal(reply['box'], ks)
    # f(n2): reverse the ASCII nonce string, easy to explain during demo.
    if answer.get('f_n2') != n2[::-1]:
        raise ValueError('Challenge failed')
    send(conn, {'type': 'ready'})
    return ks


def listen(conn, ks):
    while True:
        msg = receive(conn)
        if msg.get('type') == 'renew':
            print('\nAlice meminta session key baru.')
            return
        if msg.get('type') != 'chat':
            raise ValueError('Invalid message type')
        text = open_seal(msg['box'], ks)['text']
        print(f"\n  ciphertext: {msg['box']['ciphertext']}\nAlice: {text}\nBob > ", end='', flush=True)


def serve(server, state):
    while True:
        conn, addr = server.accept()
        with conn:
            print('\nAlice terhubung:', addr)
            try:
                state['ks'] = handshake(conn, state['kb'])
                state['conn'] = conn
                print('5 langkah sukses. Chat AES siap!\nBob > ', end='', flush=True)
                listen(conn, state['ks'])
            except Exception as e:
                print('\nSesi selesai:', e)
            finally:
                state['conn'] = None
        print('Menunggu koneksi Alice berikutnya...\nBob > ', end='', flush=True)


def run(host, port):
    state = {'kb': read_key('Kb (Bob-KDC)'), 'conn': None, 'ks': None}
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    threading.Thread(target=serve, args=(server, state), daemon=True).start()
    print('Bob siap di', host, port, '| menunggu Alice...')
    print('Perintah: /kb ganti Kb, /quit keluar. Ketik pesan setelah sesi siap.')
    while True:
        message = input('Bob > ')
        if message == '/quit':
            break
        if message == '/kb':
            state['kb'] = read_key('Kb baru')
            print('Kb baru dipakai untuk ticket berikutnya.')
            continue
        if not message:
            continue
        conn, ks = state['conn'], state['ks']
        if conn is None:
            print('Belum ada sesi dengan Alice.')
            continue
        try:
            message.encode('ascii')
            box = seal({'text': message}, ks)
            send(conn, {'type': 'chat', 'box': box})
            print('  ciphertext:', box['ciphertext'])
        except UnicodeEncodeError:
            print('Pesan harus ASCII')
        except OSError as e:
            print('Gagal kirim:', e)
    server.close()


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--host', default='0.0.0.0')
    p.add_argument('--port', type=int, default=5002)
    a = p.parse_args()
    run(a.host, a.port)
