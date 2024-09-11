from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.number import inverse

def generate_keypair(nlength=1024):
    """Generates a public/private key pair"""
    key = RSA.generate(nlength)
    pub_key = key.publickey()
    return pub_key, key

def encrypt(pub_key, message):
    """Encrypts a message using the public key"""
    e = pub_key.e
    n = pub_key.n
    ciphertext = pow(message, e, n)
    return ciphertext

def decrypt(priv_key, ciphertext):
    """Decrypts a ciphertext using the private key"""
    d = priv_key.d
    n = priv_key.n
    message = pow(ciphertext, d, n)
    return message

def main():
    # Generate key pair
    pub_key, priv_key = generate_keypair()

    # Encrypt integers
    a = 7
    b = 3
    ciphertext_a = encrypt(pub_key, a)
    ciphertext_b = encrypt(pub_key, b)

    # Perform multiplicative homomorphic operation (multiply ciphertexts)
    ciphertext_product = (ciphertext_a * ciphertext_b) % pub_key.n

    # Decrypt the result
    decrypted_product = decrypt(priv_key, ciphertext_product)

    # Print results
    print(f"Ciphertext of a: {ciphertext_a}")
    print(f"Ciphertext of b: {ciphertext_b}")
    print(f"Ciphertext of a * b: {ciphertext_product}")
    print(f"Decrypted product: {decrypted_product}")
    print(f"Expected product: {a * b}")

if __name__ == "__main__":
    main()

"""
Output:
Ciphertext of a: 21051445541878545751884862556424030197898411098029744973826450847188020460241223217367730441849667380545025769511557220346793434825286004333737830595284329664181210901341377335630082068340191697794015831577505804346838155806429307942630324498534685440567841045153528302264494335094793116880620240715103773518
Ciphertext of b: 40830189078640980656881493751470915322580531218198144640038938831642635989431440991216988223692170830176012859052433815796994316944685838512194314969907978977162640088515568816741902278863077888847541769039358041552418209096281485115672390834475291983059284381799378131268612544424895367768586249913166422991
Ciphertext of a * b: 77452143022976368900006932914935741669267184361882150431052995890825578175060147155717676518160757577140348977459396563457074502679522079476652003222927125157287793792334940809094140255216664709426070578789227483301106438320434091032469950156955855486065562468854609943242151795025384232007933525830000204362
Decrypted product: 21
Expected product: 21
"""