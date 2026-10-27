"""Alice initiates the KDC protocol and opens an interactive bidirectional chat."""
import argparse
import secrets
import socket
import threading
from protocol import receive, send, open_seal, seal, read_key, connect


def handshake(kdc_host, kdc_port, bob_host, bob_port, ka):
    n1 = secrets.token_hex(16)
    with connect(kdc_host, kdc_port) as kdc:
        send(kdc, {'type': 'request', 'from': 'alice', 'to': 'bob', 'n1': n1})
        print('(1) Request ke KDC: alice || bob || N1 =', n1)
        response = receive(kdc)

    if response.get('type') != 'kdc_reply':
        raise ValueError('KDC rejected request')

    print('(2) Balasan KDC E(Ka, ...):', response['for_alice']['ciphertext'])
    data = open_seal(response['for_alice'], ka)

    if data.get('n1') != n1 or data.get('alice') != 'alice' or data.get('bob') != 'bob':
        raise ValueError('KDC reply invalid')

    ks = data['ks'].encode('ascii')
    if len(ks) != 16:
        raise ValueError('Bad Ks')

    bob = connect(bob_host, bob_port)
    try:
        send(bob, {'type': 'ticket', 'ticket': response['ticket']})
        print('(3) Ticket ke Bob E(Kb, ...):', response['ticket']['ciphertext'])

        challenge = receive(bob)
        if challenge.get('type') != 'challenge':
            raise ValueError('Bad challenge')

        print('(4) Challenge E(Ks, N2):', challenge['box']['ciphertext'])
        n2 = open_seal(challenge['box'], ks)['n2']

        answer = seal({'f_n2': n2[::-1]}, ks)
        send(bob, {'type': 'challenge_response', 'box': answer})
        print('(5) Jawaban E(Ks, f(N2)):', answer['ciphertext'])

        if receive(bob).get('type') != 'ready':
            raise ValueError('Bob rejected challenge')

    except BaseException:
        bob.close()
        raise

    bob.settimeout(None)
    return bob, ks


def chat(bob, ks, keys):
    alive = threading.Event()
    alive.set()

    def reader():
        while alive.is_set():
            try:
                msg = receive(bob)
                if msg.get('type') != 'chat':
                    raise ValueError('Unexpected message')

                text = open_seal(msg['box'], ks)['text']
                print(
                    f"\n  ciphertext: {msg['box']['ciphertext']}"
                    f"\nBob: {text}\nAlice > ",
                    end='', flush=True
                )

            except Exception as e:
                if alive.is_set():
                    print('\nKoneksi terputus:', e, '(tekan Enter)')
                alive.clear()

    threading.Thread(target=reader, daemon=True).start()

    while alive.is_set():
        message = input('Alice > ')

        if not alive.is_set():
            break

        if message == '/ka':
            print('Ka hanya diganti saat tidak ada sesi aktif. Gunakan /renew, lalu /ka di menu.')
            continue

        try:
            if message in ('/renew', '/quit'):
                alive.clear()

                if message == '/renew':
                    print('Meminta Ks baru: sesi lama ditutup, lalu protokol 5 langkah diulang.')
                    send(bob, {'type': 'renew'})

                bob.shutdown(socket.SHUT_WR)
                return message

            message.encode('ascii')
            box = seal({'text': message}, ks)

            send(bob, {'type': 'chat', 'box': box})
            print('  ciphertext:', box['ciphertext'])

        except UnicodeEncodeError:
            print('Pesan harus ASCII')
        except OSError as e:
            print('Gagal kirim:', e)
            alive.clear()

    return 'closed'


def menu(keys):
    while True:
        choice = input(
            '[Enter] mulai sesi lagi, /ka ganti Ka, /quit keluar > '
        ).strip()

        if choice == '/ka':
            keys['ka'] = read_key('Ka baru')
        elif choice in ('', '/quit'):
            return choice


def run(kdc_host, kdc_port, bob_host, bob_port):
    keys = {'ka': read_key('Ka (Alice-KDC)')}
    command = ''

    while command != '/quit':
        try:
            bob, ks = handshake(
                kdc_host, kdc_port, bob_host, bob_port, keys['ka']
            )

        except (OSError, ValueError, KeyError, UnicodeError) as e:
            print('Sesi gagal:', e)
            command = menu(keys)
            continue

        print(
            '5 langkah selesai! Perintah: '
            '/renew Ks baru, /ka informasi, /quit keluar.'
        )

        with bob:
            command = chat(bob, ks, keys)

        if command == 'closed':
            command = menu(keys)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--kdc-host', required=True)
    p.add_argument('--kdc-port', type=int, default=5001)
    p.add_argument('--bob-host', required=True)
    p.add_argument('--bob-port', type=int, default=5002)

    a = p.parse_args()
    run(a.kdc_host, a.kdc_port, a.bob_host, a.bob_port)