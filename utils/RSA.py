import random

def is_prime(num, test_count):
    if num == 1:
        return False
    if test_count >= num:
        test_count = num - 1
    for x in range(test_count):
        val = random.randint(1, num - 1)
        if pow(val, num-1, num) != 1:
            return False
    return True

def generate_big_prime(n):
    found_prime = False
    while not found_prime:
        p = random.randint(2**(n-1), 2**n)
        if is_prime(p, 1000):
            return p

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    x, lastx, y, lasty = 0, 1, 1, 0
    while b != 0:
        q, r = divmod(a, b)
        a, b = b, r
        x, lastx = lastx - q * x, x
        y, lasty = lasty - q * y, y
    return lastx, lasty

def multiplicative_inverse(e, n):
    x, y = extended_gcd(e, n)
    if x < 0:
        return n + x
    return x

def generate_keypair(p=173, q=149):
    if p == q:
        raise ValueError('p and q cannot be equal')
    n = p * q
    phi = (p-1) * (q-1)
    while True:
        e = random.randint(3, phi - 1)
        if gcd(e, phi) == 1:
            break
    d = multiplicative_inverse(e, phi)
    return ((e, n), (d, n))

a, b = generate_keypair(generate_big_prime(8),generate_big_prime(8))

def encrypt_rsa(public_key, plaintext):
    key, n = public_key
    cipher = [(ord(char) ** key) % n for char in plaintext]
    cipher = ' '.join(str(e) for e in cipher)
    return cipher

def decrypt_rsa(private_key, ciphertext):
    d, n = private_key
    ciphertext = ciphertext.split()
    ciphertext_temp = []
    for temp in ciphertext:
        ciphertext_temp.append(int(temp))
    plain = [chr((char ** d) % n) for char in ciphertext_temp]
    return ''.join(plain)