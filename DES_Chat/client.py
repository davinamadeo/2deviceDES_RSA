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

class DES:
    # Initial Permutation
    IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

    FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

    E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13,
         14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

    S_BOXES = [
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 0, 5],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 15, 3, 12, 0],
         [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13]],
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        [[7, 13, 14, 3, 4, 15, 2, 8, 1, 10, 6, 12, 11, 0, 9, 5],
         [6, 0, 13, 9, 15, 7, 0, 10, 3, 1, 4, 2, 7, 12, 8, 2],
         [13, 1, 7, 0, 6, 10, 4, 13, 14, 0, 7, 11, 5, 8, 15, 14],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8]],
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 2, 10, 1, 7, 6, 4, 10, 13, 6, 15, 0, 9, 3]],
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 5, 12, 1, 9, 15, 14, 4, 3, 10, 7, 2, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 4, 0, 9, 14, 3, 15, 2, 5]],
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 6, 11, 13, 0, 5, 3, 4, 9, 15, 10, 8, 12]],
    ]

    P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
         2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

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
        key = key[:8] if len(key) > 8 else key
        return key + '\0' * (8 - len(key)) if len(key) < 8 else key

    def encrypt(self, plaintext: str, key: str) -> str:
        key = self.normalize_key(key)
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
        cipher_bytes = bytes(int(ciphertext_bits[i:i + 8], 2) for i in range(0, len(ciphertext_bits), 8))
        return binascii.hexlify(cipher_bytes).decode('ascii')

    def decrypt(self, ciphertext_hex: str, key: str) -> str:
        key = self.normalize_key(key)
        try:
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
        plain_bytes = bytes(int(plaintext_bits[i:i + 8], 2) for i in range(0, len(plaintext_bits), 8))
        plaintext = plain_bytes.decode('ascii', errors='ignore')
        return plaintext.rstrip('\0')


# RSA Functions
def rsa_encrypt_bytes(data: bytes, n: int, e: int) -> int:
    m = int.from_bytes(data, 'big')
    if m >= n:
        raise ValueError('message too large for modulus')
    c = pow(m, e, n)
    return c


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


class ChatClient:
    def __init__(self, host: str, port: int, username: str, use_rsa: bool, manual_key: str = None):
        self.host = host
        self.port = port
        self.username = username
        self.use_rsa = use_rsa
        self.manual_key = manual_key
        self.key_str = None
        self.des = DES()
        self.socket = None
        self.running = False

    def connect(self):
        try:
            self.socket = socket.create_connection((self.host, self.port))
            
            # RSA Handshake
            if self.use_rsa:
                hdr = recv_n(self.socket, 4)
                length = struct.unpack('>I', hdr)[0]
                data = recv_n(self.socket, length)
                txt = data.decode('ascii')
                
                if not txt.startswith('PUB:'):
                    print('Unexpected server handshake')
                    return False
                
                parts = txt.split(':')
                n = int(parts[1], 16)
                e = int(parts[2], 16)
                
                # Generate DES key
                key_bytes = os.urandom(8)
                self.key_str = key_bytes.decode('latin-1')
                
                # Encrypt and send key
                cipher_int = rsa_encrypt_bytes(key_bytes, n, e)
                cipher_hex = format(cipher_int, 'x')
                kb_msg = f'KEY:{cipher_hex}'.encode('ascii')
                self.socket.sendall(len(kb_msg).to_bytes(4, 'big') + kb_msg)
                print(f'[Secure] RSA handshake successful, DES key established')
            else:
                self.key_str = self.manual_key
            
            # Send username
            username_encrypted = self.des.encrypt(self.username, self.key_str)
            payload = username_encrypted.encode('ascii')
            self.socket.sendall(len(payload).to_bytes(4, 'big') + payload)
            
            # Wait for confirmation
            hdr = recv_n(self.socket, 4)
            length = struct.unpack('>I', hdr)[0]
            data = recv_n(self.socket, length)
            response_hex = data.decode('ascii')
            response = self.des.decrypt(response_hex, self.key_str)
            
            if response == "USERNAME_TAKEN":
                print(f'Error: Username "{self.username}" is already taken')
                return False
            elif response == "CONNECTED":
                print(f'[Connected] Welcome to the chat, {self.username}!')
                print('Type your messages below. Type "/quit" to exit.\n')
                self.running = True
                return True
            
        except ConnectionRefusedError:
            print(f'Connection refused: Server not running at {self.host}:{self.port}')
            return False
        except Exception as e:
            print(f'Connection error: {e}')
            return False

    def receive_messages(self):
        """Thread for receiving messages from server"""
        while self.running:
            try:
                hdr = self.socket.recv(4)
                if not hdr:
                    break
                if len(hdr) < 4:
                    hdr += recv_n(self.socket, 4 - len(hdr))
                
                length = struct.unpack('>I', hdr)[0]
                data = recv_n(self.socket, length)
                cipher_hex = data.decode('ascii')
                plaintext = self.des.decrypt(cipher_hex, self.key_str)
                
                print(f'\r{plaintext}')
                print(f'[You]: ', end='', flush=True)
            
            except ConnectionError:
                break
            except Exception as e:
                if self.running:
                    print(f'\nError receiving message: {e}')
                break

    def send_messages(self):
        """Main loop for sending messages"""
        print(f'[You]: ', end='', flush=True)
        while self.running:
            try:
                message = input()
                
                if message.strip().lower() == '/quit':
                    print('Disconnecting...')
                    self.running = False
                    break
                
                if message.strip():
                    encrypted = self.des.encrypt(message, self.key_str)
                    payload = encrypted.encode('ascii')
                    self.socket.sendall(len(payload).to_bytes(4, 'big') + payload)
                
                if self.running:
                    print(f'[You]: ', end='', flush=True)
            
            except KeyboardInterrupt:
                print('\nDisconnecting...')
                self.running = False
                break
            except Exception as e:
                if self.running:
                    print(f'Error sending message: {e}')
                break

    def start(self):
        if not self.connect():
            return
        
        # Start receive thread
        receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receive_thread.start()
        
        # Send messages in main thread
        self.send_messages()
        
        # Cleanup
        if self.socket:
            self.socket.close()


def main():
    print("=== DES + RSA Chat Client ===")
    host = input('Server IP: ').strip()
    port_s = input('Server Port [9999]: ').strip()
    port = int(port_s) if port_s else 9999
    
    username = input('Enter your username: ').strip()
    if not username:
        print('Username cannot be empty')
        return
    
    use_rsa_input = input('Use RSA key distribution? [Y/n]: ').strip().lower()
    use_rsa = (use_rsa_input != 'n')
    
    manual_key = None
    if not use_rsa:
        key_in = input('Enter DES key (8 chars or 16 hex): ')
        try:
            manual_key = parse_key_input(key_in)
        except Exception as e:
            print(f'Invalid key: {e}')
            return
    
    print('\nConnecting...')
    client = ChatClient(host, port, username, use_rsa, manual_key)
    client.start()


if __name__ == "__main__":
    main()
