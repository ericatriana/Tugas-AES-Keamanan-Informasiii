# AES-128 + Key Distribution Center

Tugas 2 Keamanan Informasi. Alice dan Bob bertukar pesan terenkripsi AES-128 setelah mendapatkan session key dari KDC lewat protokol lima langkah. AES dan KDC ditulis manual, tanpa pustaka kriptografi pihak ketiga.

## Anggota

| Nama | NRP | GitHub |
|---|---|---|
| Erica Triana W. | 5025241069 | ericatriana |
| Nasyita Larasati E. | 5025241201 | imstunning |

## Cara kerja singkat

Alice dan Bob belum punya kunci bersama. KDC (pihak ketiga tepercaya) membuat session key (Ks) dan membagikannya dalam bentuk terenkripsi, sehingga Ks tidak pernah lewat jaringan dalam keadaan terbuka.

- **Ka**: key rahasia Alice dan KDC.
- **Kb**: key rahasia Bob dan KDC.
- **Ks**: session key untuk chat Alice dan Bob, dibuat KDC setiap sesi.

![Key Distribution Scenario](images/key-distribution.jpg)

*Skenario Key Distribution pada ketentuan tugas: langkah 1 sampai 3 adalah distribusi kunci, langkah 4 dan 5 adalah autentikasi.*

| No | Arah | Pesan |
|---|---|---|
| 1 | Alice → KDC | `ID_A ‖ ID_B ‖ N1` |
| 2 | KDC → Alice | `E(Ka, [Ks ‖ ID_A ‖ ID_B ‖ N1]) ‖ E(Kb, [Ks ‖ ID_A])` |
| 3 | Alice → Bob | `E(Kb, [Ks ‖ ID_A])` |
| 4 | Bob → Alice | `E(Ks, N2)` |
| 5 | Alice → Bob | `E(Ks, f(N2))`, dengan f = membalik urutan karakter N2 |

Setelah langkah 5, setiap pesan chat dienkripsi dengan Ks.

## Fitur

**Sesuai ketentuan tugas**

- AES-128 manual (SubBytes, ShiftRows, MixColumns, AddRoundKey, key expansion)
- KDC dan protokol lima langkah sesuai diagram
- Tiga entitas di tiga IP berbeda
- Chat dua arah, key dan plaintext ASCII, ciphertext ditampilkan dalam hex
- Key diinput saat program berjalan dan dapat diganti tanpa menjalankan ulang program (`/ka`, `/kb`)

**Tambahan**

- Mode CBC dengan IV acak: pesan yang sama menghasilkan ciphertext berbeda
- HMAC-SHA256: ciphertext yang diubah atau key yang salah ditolak
- `/renew`: Alice meminta session key baru dari KDC tanpa menjalankan ulang program

## Menjalankan

Python 3.9 atau lebih baru, hanya pustaka standar. Jalankan berurutan: KDC, Bob, Alice. Isi Ka di KDC dan Alice, Kb di KDC dan Bob (masing-masing 16 karakter ASCII).

```bash
# Perangkat 1: KDC
python kdc.py --port 5001

# Perangkat 2: Bob
python bob.py --port 5002

# Perangkat 3: Alice
python alice.py --kdc-host <IP_KDC> --bob-host <IP_BOB>
```

Gunakan `python3` di macOS dan Linux.

| Program | Perintah |
|---|---|
| KDC | `/ka`, `/kb`, `/quit` |
| Alice | ketik pesan, `/renew`, `/quit` |
| Bob | ketik pesan, `/kb`, `/quit` |

## Struktur

```
aes.py        AES-128 manual dan mode CBC
protocol.py   pengiriman pesan lewat TCP, enkripsi dan HMAC
kdc.py        KDC
alice.py      Alice (initiator)
bob.py        Bob (responder)
tests/        tes unit
```

## Tes

```bash
python -m unittest discover -s tests -v
```

Mencakup test vector NIST AES-128, round-trip CBC, IV acak, penolakan HMAC, dan `/renew`.

## Dokumentasi lengkap

Persiapan jaringan, langkah menjalankan di tiga perangkat, skenario pengujian, panduan Wireshark, dan daftar kesalahan umum ada di [PENGUJIAN.md](PENGUJIAN.md).

## Keterbatasan

Protokol ini varian Needham–Schroeder symmetric key. Ticket tidak memiliki timestamp, sehingga jika suatu Ks lama bocor, ticket lama dapat diputar ulang (*replay*, serangan Denning–Sacco). Implementasi ini untuk keperluan pembelajaran, bukan untuk melindungi data nyata.
