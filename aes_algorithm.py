# -*- coding: utf-8 -*-
from aes_tables import S_BOX, INV_S_BOX

def pad_zero(data, block_size=16):
    padding_needed = (block_size - (len(data) % block_size)) % block_size
    return data + [0x00] * padding_needed

def split_blocks(data, block_size=16):
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

def bytes_to_state_columnwise(data):
    state = [[0] * 4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = data[col * 4 + row]
    return state

def state_to_bytes_columnwise(state):
    result = []
    for col in range(4):
        for row in range(4):
            result.append(state[row][col])
    return result

def xor_states(a, b):
    return [[a[r][c] ^ b[r][c] for c in range(4)] for r in range(4)]

def sub_bytes(state):
    return [[S_BOX[v >> 4][v & 0x0F] for v in row] for row in state]

def inv_sub_bytes(state):
    return [[INV_S_BOX[v >> 4][v & 0x0F] for v in row] for row in state]

def shift_rows(state):
    result = [row[:] for row in state]
    for r in range(4):
        result[r] = state[r][r:] + state[r][:r]
    return result

def inv_shift_rows(state):
    result = [row[:] for row in state]
    for r in range(4):
        result[r] = state[r][-r:] + state[r][:-r] if r else state[r][:]
    return result

def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p

def mix_single_column(col):
    a0, a1, a2, a3 = col
    return [
        gmul(a0, 2) ^ gmul(a1, 3) ^ gmul(a2, 1) ^ gmul(a3, 1),
        gmul(a0, 1) ^ gmul(a1, 2) ^ gmul(a2, 3) ^ gmul(a3, 1),
        gmul(a0, 1) ^ gmul(a1, 1) ^ gmul(a2, 2) ^ gmul(a3, 3),
        gmul(a0, 3) ^ gmul(a1, 1) ^ gmul(a2, 1) ^ gmul(a3, 2),
    ]

def inv_mix_single_column(col):
    a0, a1, a2, a3 = col
    return [
        gmul(a0, 0x0E) ^ gmul(a1, 0x0B) ^ gmul(a2, 0x0D) ^ gmul(a3, 0x09),
        gmul(a0, 0x09) ^ gmul(a1, 0x0E) ^ gmul(a2, 0x0B) ^ gmul(a3, 0x0D),
        gmul(a0, 0x0D) ^ gmul(a1, 0x09) ^ gmul(a2, 0x0E) ^ gmul(a3, 0x0B),
        gmul(a0, 0x0B) ^ gmul(a1, 0x0D) ^ gmul(a2, 0x09) ^ gmul(a3, 0x0E),
    ]

def mix_columns(state):
    result = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed = mix_single_column(col)
        for r in range(4):
            result[r][c] = mixed[r]
    return result

def inv_mix_columns(state):
    result = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed = inv_mix_single_column(col)
        for r in range(4):
            result[r][c] = mixed[r]
    return result

def clean_zero_padding(data):
    while data and data[-1] == 0:
        data.pop()
    return data

def text_to_bytes(text):
    return list(text.encode("utf-8"))

def bytes_to_text(data):
    return bytes(data).decode("utf-8", errors="replace")

def prepare_key(key_text):
    key_bytes = text_to_bytes(key_text)
    key_bytes = pad_zero(key_bytes, 16)
    return bytes_to_state_columnwise(key_bytes[:16])

def encrypt_block(block_bytes, key_state):
    state = bytes_to_state_columnwise(block_bytes)
    state = xor_states(state, key_state)
    state = sub_bytes(state)
    state = shift_rows(state)
    return mix_columns(state)

def decrypt_block(cipher_state, key_state):
    state = inv_mix_columns(cipher_state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    return xor_states(state, key_state)

def states_to_hex_string(states):
    all_bytes = []
    for state in states:
        all_bytes.extend(state_to_bytes_columnwise(state))
    return "".join(f"{b:02X}" for b in all_bytes)

def hex_string_to_states(hex_text):
    hex_text = hex_text.strip().replace(" ", "")
    if len(hex_text) % 32 != 0:
        raise ValueError("Ciphertext hex length must be a multiple of 32 hex characters.")
    all_bytes = [int(hex_text[i:i+2], 16) for i in range(0, len(hex_text), 2)]
    return [bytes_to_state_columnwise(block) for block in split_blocks(all_bytes, 16)]

def encrypt_message(plaintext, key_text):
    text_bytes = text_to_bytes(plaintext)
    padded = pad_zero(text_bytes, 16)
    if not padded:
        padded = [0] * 16
    key_state = prepare_key(key_text)
    cipher_states = [encrypt_block(block, key_state) for block in split_blocks(padded, 16)]
    return states_to_hex_string(cipher_states)

def decrypt_message(cipher_hex, key_text):
    key_state = prepare_key(key_text)
    cipher_states = hex_string_to_states(cipher_hex)
    recovered_bytes = []
    for cipher_state in cipher_states:
        recovered_state = decrypt_block(cipher_state, key_state)
        recovered_bytes.extend(state_to_bytes_columnwise(recovered_state))
    return bytes_to_text(clean_zero_padding(recovered_bytes))

def menu():
    print("\nAES Algorithm :\n")
    print("1) Encrypt text")
    print("2) Decrypt text")
    print("3) Full Process")
    print("4) Exit")

def main():
    while True:
        menu()
        choice = input("Choose: ").strip()

        if choice == "1":
            plaintext = input("Enter plaintext: ")
            key = input("Enter key: ")
            cipher_hex = encrypt_message(plaintext, key)
            print("\nEncrypted text (HEX):")
            print(cipher_hex)

        elif choice == "2":
            cipher_hex = input("Enter ciphertext hex: ")
            key = input("Enter key: ")
            try:
                plaintext = decrypt_message(cipher_hex, key)
                print("\nDecrypted text:")
                print(plaintext)
            except Exception as e:
                print(f"Error: {e}")

        elif choice == "3":
            plaintext = input("Enter plaintext: ")
            key = input("Enter key: ")
            cipher_hex = encrypt_message(plaintext, key)
            print("\nEncrypted text (HEX):")
            print(cipher_hex)
            decrypted = decrypt_message(cipher_hex, key)
            print("\nDecrypted text:")
            print(decrypted)

        elif choice == "4":
            print("Goodbye")
            break

        else:
            print("Invalid choice, try again.")

if __name__ == "__main__":
    main()