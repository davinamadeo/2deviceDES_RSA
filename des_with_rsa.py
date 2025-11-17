from typing import List
import binascii
import socket
import struct
import threading
import sys
import string
import os
import random
import math
import time

class DES:
    # Initial Permutation
    IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

    # Final Permutation
    FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

    # Expansion table untuk fungsi F
    E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13,
         14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

    # S-boxes
    S_BOXES = [
        # S1
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 0, 5],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        # S2
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 15, 3, 12, 0],
         [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13]],
        # S3
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        # S4
        [[7, 13, 14, 3, 4, 15, 2, 8, 1, 10, 6, 12, 11, 0, 9, 5],
         [6, 0, 13, 9, 15, 7, 0, 10, 3, 1, 4, 2, 7, 12, 8, 2],
         [13, 1, 7, 0, 6, 10, 4, 13, 14, 0, 7, 11, 5, 8, 15, 14],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8]],
        # S5
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 2, 10, 1, 7, 6, 4, 10, 13, 6, 15, 0, 9, 3]],
        # S6
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        # S7
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 5, 12, 1, 9, 15, 14, 4, 3, 10, 7, 2, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 4, 0, 9, 14, 3, 15, 2, 5]],
        # S8
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 6, 11, 13, 0, 5, 3, 4, 9, 15, 10, 8, 12]],
    ]

    # Permutation box P
    P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

    # Key schedule
    PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
           59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 28, 20, 12, 4,
           63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6,
           61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4, 27, 19, 11, 3]

    PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
           26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
           51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

    SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    @staticmethod
    def permute(data: List[int], perm_table: List[int]) -> List[int]:
        return [data[perm_table[i] - 1] for i in range(len(perm_table))]

    @staticmethod
    def xor(a: List[int], b: List[int]) -> List[int]:
        return [x ^ y for x, y in zip(a, b)]

    @staticmethod
    def rotate_left(data: List[int], n: int) -> List[int]:
        return data[n:] + data[:n]

    def key_schedule(self, key: List[int]) -> List[List[int]]:
        keys = []
        key = self.permute(key, self.PC1)
        c, d = key[:28], key[28:]

        for i in range(16):
            c = self.rotate_left(c, self.SHIFTS[i])
            d = self.rotate_left(d, self.SHIFTS[i])
            combined = c + d
            keys.append(self.permute(combined, self.PC2))

        return keys

    def f_function(self, r: List[int], k: List[int]) -> List[int]:
        r_expanded = self.permute(r, self.E)
        r_xor_k = self.xor(r_expanded, k)

        output = []
        for i in range(8):
            s_box = self.S_BOXES[i]
            row_bits = [r_xor_k[i * 6], r_xor_k[i * 6 + 5]]
            row = int(''.join(map(str, row_bits)), 2)
            col_bits = r_xor_k[i * 6 + 1:i * 6 + 5]
            col = int(''.join(map(str, col_bits)), 2)
            value = s_box[row][col]
            output.extend([int(b) for b in format(value, '04b')])

        return self.permute(output, self.P)

    def encrypt_block(self, plaintext: List[int], keys: List[List[int]]) -> List[int]:
        block = self.permute(plaintext, self.IP)
        l, r = block[:32], block[32:]

        for i in range(16):
            f_out = self.f_function(r, keys[i])
            l, r = r, self.xor(l, f_out)

        final_block = r + l
        return self.permute(final_block, self.FP)

    def decrypt_block(self, ciphertext: List[int], keys: List[List[int]]) -> List[int]:
        block = self.permute(ciphertext, self.IP)
        l, r = block[:32], block[32:]

        for i in range(15, -1, -1):
            f_out = self.f_function(r, keys[i])
            l, r = r, self.xor(l, f_out)

        final_block = r + l
        return self.permute(final_block, self.FP)

    def normalize_key(self, key: str) -> str:
        """Normalisasi key ke 8 karakter"""
        key = key[:8] if len(key) > 8 else key
        return key + '\0' * (8 - len(key)) if len(key) < 8 else key

    def encrypt(self, plaintext: str, key: str) -> str:
        """Enkripsi plaintext dengan key"""
        key = self.normalize_key(key)
        
        # Padding plaintext ke kelipatan 8
        if len(plaintext) % 8 != 0:
            plaintext = plaintext + '\0' * (8 - len(plaintext) % 8)
        
        pt_bits = ''.join(format(ord(c), '08b') for c in plaintext)
        k_bits = ''.join(format(ord(c), '08b') for c in key)
        
        keys = self.key_schedule([int(b) for b in k_bits])
        ciphertext_bits = ''
        
        for i in range(0, len(pt_bits), 64):
            block = [int(b) for b in pt_bits[i:i + 64]]
            encrypted = self.encrypt_block(block, keys)
            ciphertext_bits += ''.join(map(str, encrypted))
        
        # Konversi ke hex untuk menghindari karakter non-printable
        cipher_bytes = bytes(int(ciphertext_bits[i:i + 8], 2) for i in range(0, len(ciphertext_bits), 8))
        return binascii.hexlify(cipher_bytes).decode('ascii')

    def decrypt(self, ciphertext_hex: str, key: str) -> str:
        """Dekripsi ciphertext (format hex) dengan key"""
        key = self.normalize_key(key)
        
        try:
            # Konversi dari hex ke bytes
            cipher_bytes = binascii.unhexlify(ciphertext_hex)
            ct_bits = ''.join(format(byte, '08b') for byte in cipher_bytes)
        except Exception as e:
            raise ValueError(f"Format ciphertext salah: {e}")
        
        k_bits = ''.join(format(ord(c), '08b') for c in key)
        
        keys = self.key_schedule([int(b) for b in k_bits])
        plaintext_bits = ''
        
        for i in range(0, len(ct_bits), 64):
            block = [int(b) for b in ct_bits[i:i + 64]]
            decrypted = self.decrypt_block(block, keys)
            plaintext_bits += ''.join(map(str, decrypted))
        
        # Konversi bits ke karakter
        plain_bytes = bytes(int(plaintext_bits[i:i + 8], 2) for i in range(0, len(plaintext_bits), 8))
        plaintext = plain_bytes.decode('ascii', errors='ignore')
        
        return plaintext.rstrip('\0')

def is_probable_prime(n: int, k: int = 8) -> bool:
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 = d * 2^s
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    # witness test
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True

def generate_prime(bits: int) -> int:
    while True:
        p = random.getrandbits(bits) | (1 << (bits - 1)) | 1  # ensure high bit and odd
        if is_probable_prime(p):
            return p

def egcd(a: int, b: int):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError('modinv does not exist')
    return x % m

def generate_rsa_keypair(bits: int = 512):
    # generate p, q
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while q == p:
        q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    # choose e
    e = 65537
    if math.gcd(e, phi) != 1:
        # fallback
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)
    return (n, e, d)

def rsa_encrypt_bytes(data: bytes, n: int, e: int) -> int:
    m = int.from_bytes(data, 'big')
    if m >= n:
        raise ValueError('message too large for modulus')
    c = pow(m, e, n)
    return c

def rsa_decrypt_to_bytes(cipher_int: int, n: int, d: int) -> bytes:
    m = pow(cipher_int, d, n)
    # compute length in bytes
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(length, 'big')

def recv_n(sock: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError('connection closed')
        data.extend(chunk)
    return bytes(data)

def parse_key_input(k: str) -> str:
    k = k.strip()
    if len(k) == 8:
        return k
    if len(k) == 16 and all(c in string.hexdigits for c in k):
        b = bytes.fromhex(k)
        return b.decode('latin-1')
    raise ValueError('Key must be 8 ASCII characters or 16 hex digits')

def run_server(host: str, port: int, manual_key: str | None, use_rsa_dist: bool):
    des = DES()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(5)
    print(f'DES receiver listening on {host}:{port} (RSA key-dist={"on" if use_rsa_dist else "off"})')

    def handle_conn(conn, addr):
        print(f'Client connected: {addr}')
        try:
            # handshake: either use provided manual_key or perform RSA key distribution
            if use_rsa_dist:
                # generate rsa keypair for this connection
                n, e, d = generate_rsa_keypair(bits=512)
                # send public key as ASCII header: PUB:<n_hex>:<e_hex>
                pub_msg = f'PUB:{n:x}:{e:x}'
                payload = pub_msg.encode('ascii')
                conn.sendall(len(payload).to_bytes(4, 'big') + payload)
                # receive KEY message from client
                hdr = recv_n(conn, 4)
                length = struct.unpack('>I', hdr)[0]
                data = recv_n(conn, length)
                try:
                    txt = data.decode('ascii')
                except Exception:
                    print('Received non-ascii during handshake; closing')
                    return
                if not txt.startswith('KEY:'):
                    print('Unexpected handshake msg:', txt)
                    return
                cipher_hex = txt[4:]
                try:
                    cipher_int = int(cipher_hex, 16)
                    key_bytes = rsa_decrypt_to_bytes(cipher_int, n, d)
                    # ensure exactly 8 bytes: if shorter, left-pad with zeros
                    if len(key_bytes) < 8:
                        key_bytes = (b'\x00' * (8 - len(key_bytes))) + key_bytes
                    if len(key_bytes) > 8:
                        # cut to last 8 bytes (since sender likely used os.urandom(8))
                        key_bytes = key_bytes[-8:]
                    key_str = key_bytes.decode('latin-1')
                    print(f'Established DES key via RSA with {addr}: {key_bytes.hex()}')
                except Exception as e:
                    print('Failed to decrypt DES key from client:', e)
                    return
            else:
                # manual key path: ask client to send 'REQKEY' then we proceed
                # (But in our menu, manual_key is provided locally; no network key exchange.)
                if manual_key is None:
                    print('No manual key provided; closing')
                    return
                key_str = manual_key

            # Now run recv loop expecting ciphertext hex messages as before
            while True:
                hdr = conn.recv(4)
                if not hdr:
                    break
                if len(hdr) < 4:
                    hdr += recv_n(conn, 4 - len(hdr))
                length = struct.unpack('>I', hdr)[0]
                if length == 0:
                    continue
                data = recv_n(conn, length)
                try:
                    cipher_hex = data.decode('ascii')
                except Exception:
                    print('Received non-ascii payload; skipping')
                    break
                print(f'Received ciphertext (hex) from {addr}: {cipher_hex}')
                try:
                    plaintext = des.decrypt(cipher_hex, key_str)
                except Exception as e:
                    print(f'Failed to decrypt message from {addr}: {e}')
                    break
                print(f'Decrypted plaintext from {addr}: {plaintext}')

                # send encrypted ACK
                ack_text = f'ACK: received {len(plaintext)} bytes'
                ack_hex = des.encrypt(ack_text, key_str)
                payload = ack_hex.encode('ascii')
                print(f'Sending ACK (hex): {ack_hex}')
                conn.sendall(len(payload).to_bytes(4, 'big') + payload)

        except ConnectionError:
            print(f'Connection closed by {addr}')
        except Exception as e:
            print(f'Error handling {addr}: {e}')
        finally:
            conn.close()
            print(f'Client disconnected: {addr}')

    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_conn, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print('\nReceiver shutting down')
    finally:
        srv.close()

def run_client(host: str, port: int, manual_key: str | None, use_rsa_dist: bool, message: str):
    des = DES()
    try:
        with socket.create_connection((host, port)) as s:
            if use_rsa_dist:
                # receive PUB message
                hdr = recv_n(s, 4)
                length = struct.unpack('>I', hdr)[0]
                data = recv_n(s, length)
                txt = data.decode('ascii')
                if not txt.startswith('PUB:'):
                    print('Unexpected server handshake:', txt)
                    return
                parts = txt.split(':')
                if len(parts) != 3:
                    print('Bad PUB format from server')
                    return
                n = int(parts[1], 16)
                e = int(parts[2], 16)
                # generate random 8-byte DES key
                key_bytes = os.urandom(8)
                key_str = key_bytes.decode('latin-1')
                # encrypt DES key with server public key
                cipher_int = rsa_encrypt_bytes(key_bytes, n, e)
                cipher_hex = format(cipher_int, 'x')
                kb_msg = f'KEY:{cipher_hex}'.encode('ascii')
                s.sendall(len(kb_msg).to_bytes(4, 'big') + kb_msg)
                print(f'Sent encrypted DES key to server (DES key hex {key_bytes.hex()})')
            else:
                if manual_key is None:
                    print('No manual key provided; abort')
                    return
                key_str = manual_key

            # Now send DES-encrypted message as before
            ct_hex = des.encrypt(message, key_str)
            print(f'Ciphertext (hex) to send: {ct_hex}')
            payload = ct_hex.encode('ascii')
            s.sendall(len(payload).to_bytes(4, 'big') + payload)

            # wait for reply header
            hdr = recv_n(s, 4)
            length = struct.unpack('>I', hdr)[0]
            data = recv_n(s, length)
            reply_hex = data.decode('ascii')
            reply = des.decrypt(reply_hex, key_str)
            print('Server reply (decrypted):', reply)
            print('Server reply (cipher hex):', reply_hex)

    except ConnectionRefusedError:
        print(f'Connection refused: could not connect to {host}:{port}.')
    except OSError as e:
        print(f'Network error when connecting to {host}:{port} -> {e}')

def display_menu():
    print("APLIKASI ENKRIPSI DES + RSA Key Distribution")
    print("1. Jalankan sebagai SENDER (kirim ke remote)")
    print("2. Jalankan sebagai RECEIVER (terima dari remote)")
    print("3. Keluar")

def main():
    while True:
        display_menu()
        choice = input("Pilih opsi (1-3): ").strip()

        if choice == '1':
            print('\n--- MODE SENDER ---')
            host = input('Server host/IP: ').strip()
            port_s = input('Server port [9999]: ').strip()
            port = int(port_s) if port_s else 9999
            use_pk = input('Gunakan RSA public-key distribution untuk DES key? [Y/n]: ').strip().lower()
            use_rsa = (use_pk != 'n')
            manual_key = None
            if not use_rsa:
                key_in = input('Masukkan key (8 chars or 16 hex): ')
                try:
                    manual_key = parse_key_input(key_in)
                except Exception as e:
                    print('Key invalid:', e)
                    continue
            msg = input('Message to send: ')
            if not msg:
                print('Message kosong; abort')
                continue
            run_client(host, port, manual_key, use_rsa, msg)

        elif choice == '2':
            print('\n--- MODE RECEIVER ---')
            host = input('Bind host [0.0.0.0]: ').strip() or '0.0.0.0'
            port_s = input('Bind port [9999]: ').strip()
            port = int(port_s) if port_s else 9999
            use_pk = input('Gunakan RSA public-key distribution for DES key? [Y/n]: ').strip().lower()
            use_rsa = (use_pk != 'n')
            manual_key = None
            if not use_rsa:
                key_in = input('Masukkan key (8 chars or 16 hex): ')
                try:
                    manual_key = parse_key_input(key_in)
                except Exception as e:
                    print('Key invalid:', e)
                    continue
            print('Starting receiver (CTRL-C to stop)')
            run_server(host, port, manual_key, use_rsa)

        elif choice == '3':
            break
        else:
            print('\n Opsi tidak valid! Silakan pilih 1-3.')

if __name__ == "__main__":
    main()