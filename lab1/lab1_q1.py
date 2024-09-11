plaintext = "I am learning information security"


def additive_cipher_enc(plaintext: str, key: int):
    encrypted_text = ""
    
    for c in plaintext:

        if c == " ":
            shifted_c = " "
        elif c.isupper():
            shifted_c = chr(((ord(c) - ord('A') + key) % 26) + ord('A')) 
        else:
            shifted_c = chr(((ord(c) - ord('a') + key) % 26) + ord('a'))
        
        encrypted_text += shifted_c

    return encrypted_text

def additive_cipher_dec(enc: str, key: int):
    decrypted_text = ""
    
    for c in enc:

        if c == " ":
            shifted_c = " "
        elif c.isupper():
            shifted_c = chr(((ord(c) - ord('A') - key) % 26) + ord('A')) 
        else:
            shifted_c = chr(((ord(c) - ord('a') - key) % 26) + ord('a'))
        
        decrypted_text += shifted_c

    return decrypted_text

print("\nAdditive Cipher\n")
enc = additive_cipher_enc(plaintext=plaintext, key=20)
dec = additive_cipher_dec(enc=enc, key=20)

print(enc)
print(dec)

def multiplicative_cipher_enc(plaintext: str, key: int):
    encrypted_text = ""
    
    if key == 0:
        return plaintext
    
    for c in plaintext:

        if c == " ":
            shifted_c = " "
        elif c.isupper():
            shifted_c = chr((((ord(c) - ord('A')) * key) % 26) + ord('A'))
        else:
            shifted_c = chr((((ord(c) - ord('a')) * key) % 26) + ord('a'))
        
        encrypted_text += shifted_c

    return encrypted_text

def multiplicative_cipher_dec(enc: str, key: int):
    decrypted_text = ""
    
    if key == 0:
        return enc

    key = pow(key, -1, 26)
    for c in enc:

        if c == " ":
            shifted_c = " "
        elif c.isupper():
            shifted_c = chr((((ord(c) - ord('A')) * key) % 26) + ord('A'))
        else:
            shifted_c = chr((((ord(c) - ord('a')) * key) % 26) + ord('a'))
        
        decrypted_text += shifted_c

    return decrypted_text

print("\nMultiplicative Cipher\n")
enc = multiplicative_cipher_enc(plaintext=plaintext, key=15)
dec = multiplicative_cipher_dec(enc=enc, key=15)

print(enc)
print(dec)


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    else:
        return x % m


def affine_cipher_enc(plaintext: str, key: tuple):
    a = key[0]
    b = key[1]

    encrypted_text = ""

    for c in plaintext:

        if c == " ":
            shifted_c = " "
        elif c.isupper():
            shifted_c = chr((((ord(c) - ord('A')) * a + b) % 26) + ord('A')) 
        else:
            shifted_c = chr((((ord(c) - ord('a')) * a + b) % 26) + ord('a'))
        
        encrypted_text += shifted_c

    return encrypted_text

def affine_cipher_dec(ciphertext: str, key: tuple):
    a = key[0]
    b = key[1]

    decrypted_txt = ""

    a_mod_inv = mod_inverse(a, 26)

    for c in ciphertext:

        if c == " ":
            shifted_c = " "
        elif c.isupper():
            shifted_c = chr((((ord(c) - ord('A') - b) * a_mod_inv) % 26) + ord('A')) 
        else:
            shifted_c = chr((((ord(c) - ord('a') - b) * a_mod_inv) % 26) + ord('a'))
        
        decrypted_txt += shifted_c

    return decrypted_txt

enc = affine_cipher_enc(plaintext=plaintext, key=(15,20))
dec = affine_cipher_dec(ciphertext=enc, key=(15,20))


print("\nAFFINE CIPHER\n")
print(enc)
print(dec)
