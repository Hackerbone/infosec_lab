# Analysis

Ciphertext -> CIW
Plaintext -> yes

We can calculate the shift for each letter:

For letter Y
Y = 25
C = 3

C - Y % 26 = 4

For letter E
I = 9
E = 5

I - E % 26 = 4

For letter S
W = 23
S = 19

W - S = 4

Shift = 4, Key = 4

# Attack Type
The attack used here is brute force or direct decryption of the Caesar cipher using known plaintext to determine the shift.

Encrypted Ciphertext: "XVIEWYWI".
Cipher: Caesar Cipher
Key: 4

Decrypted Plaintext: "TREASURE".