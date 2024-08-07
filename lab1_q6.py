plaintext = "AB"

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

def brute_force_affine(ciphertext, plaintext_sample):
    """Brute force to find the correct affine cipher keys given ciphertext and a sample plaintext."""
    for a in range(1, 26):
        gcd, x, y = extended_gcd(a, 26) 
        if gcd != 1:
            continue  # 'a' must be coprime with 26
        for b in range(26):
            # Test current (a, b)
            decrypted_sample = affine_decrypt(plaintext_sample, (a, b))
            if decrypted_sample == plaintext_sample:
                # If the sample plaintext matches, print the result
                print(f"Possible keys found: a = {a}, b = {b}")
                return a, b
    print("No valid keys found.")
    return None, None

def affine_decrypt(ciphertext: str, key: tuple):
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

dec = affine_decrypt(ciphertext="XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS", key=(5,6))
print(dec)

ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
plaintext_sample = "GL"  # From the given information, "ab" encodes to "GL"
brute_force_affine(ciphertext, plaintext_sample)