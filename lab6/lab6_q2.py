import random
from sympy import isprime


def generate_large_prime(bits=256):
    return next(n for n in iter(lambda: random.getrandbits(bits), None) if isprime(n))


def dh_keygen(bits=256):
    p, g = generate_large_prime(bits), random.randint(
        2, (p := generate_large_prime(bits)) - 2
    )
    a, b = random.randint(1, p - 2), random.randint(1, p - 2)
    A, B = pow(g, a, p), pow(g, b, p)
    return (p, g, A, B), (pow(B, a, p), pow(A, b, p))


(pub, (sec_A, sec_B)) = dh_keygen()
print("Public values (p, g, A, B):", *pub)
print("Shared secrets match?", sec_A == sec_B)


"""
Output:

Public values (p, g, A, B): 57362700967700179027746614187317044674120646808356604905972465806112511326147 58601255477100039570470421947914615739523804063449601475977088658831515288612 39384236907483045297374802164089030443584050728289431914118131510699584633484 42966337621924961370621816291450829649739610013752348158366030243070495895726
Shared secrets match? True
"""
