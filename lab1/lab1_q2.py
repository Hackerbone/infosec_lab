plaintext = "the house is being sold tonight"

def character_ord(character: str):
    if character.isupper():
        return ord(character) - ord('A')
    else:
        return ord(character) - ord('a')

def vignere_cipher_enc(plaintext: str, keyword: str):
    encrypted_text = ""
    key_index = 0
    key_length = len(keyword)

    for c in plaintext:

        if c == " ":
            shifted_c = " "
            encrypted_text += shifted_c
            continue
        elif c.isupper():
            shifted_c = chr(((character_ord(c) + character_ord(keyword[key_index % key_length])) % 26) + ord('A')) 
        else:
            shifted_c = chr(((character_ord(c) + character_ord(keyword[key_index % key_length])) % 26) + ord('a'))
        
        encrypted_text += shifted_c
        key_index+=1

    return encrypted_text

def vignere_cipher_dec(enc: str, keyword: str):
    decrypted_text = ""
    key_index = 0
    key_length = len(keyword)

    for c in enc:

        if c == " ":
            shifted_c = " "
            decrypted_text += shifted_c
            continue
        elif c.isupper():
            shifted_c = chr(((character_ord(c) - character_ord(keyword[key_index % key_length])) % 26) + ord('A')) 
        else:
            shifted_c = chr(((character_ord(c) - character_ord(keyword[key_index % key_length])) % 26) + ord('a'))
        
        decrypted_text += shifted_c
        key_index+=1

    return decrypted_text

print("\nVignere Cipher\n")
enc = vignere_cipher_enc(plaintext=plaintext, keyword="dollars")
dec = vignere_cipher_dec(enc=enc, keyword="dollars")

print(enc)
print(dec)

def autokey_cipher_enc(plaintext: str, key: int):
    encrypted_text = ""
    
    key_arr = [key]
    key_index = 0

    for c in plaintext:

        if c == " ":
            shifted_c = " "
            encrypted_text += shifted_c
            continue
        elif c.isupper():
            shifted_c = chr(((character_ord(c) + key_arr[key_index]) % 26) + ord('A'))
            key_arr.append(character_ord(shifted_c))
        else:
            shifted_c = chr(((character_ord(c) + key_arr[key_index]) % 26) + ord('a'))
            key_arr.append(character_ord(shifted_c))

        encrypted_text += shifted_c
        key_index+=1

    return encrypted_text

def autokey_cipher_dec(enc: str, key: int):
    decrypted_text = ""
    key_arr = [key]
    for i in enc:
        if i == " ":
            continue
        key_arr.append(character_ord(i))

    key_index = 0

    for c in enc:

        if c == " ":
            shifted_c = " "
            decrypted_text += shifted_c
            continue
        elif c.isupper():
            shifted_c = chr(((character_ord(c) - key_arr[key_index]) % 26) + ord('A')) 
        else:
            shifted_c = chr(((character_ord(c) - key_arr[key_index]) % 26) + ord('a'))
        
        decrypted_text += shifted_c
        key_index+=1

    return decrypted_text


print("\nAutokey Cipher\n")
enc = autokey_cipher_enc(plaintext=plaintext, key=7)
dec = autokey_cipher_dec(enc=enc, key=7)

print(enc)
print(dec)

