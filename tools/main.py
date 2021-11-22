from sha256 import sha256
import utils


def genKey():
    p = 0
    q = 0
    while (p == q):
        p = utils.genPrimeRange(10**100, 10**101)
        q = utils.genPrimeRange(10**100, 10**101)
    n = p * q
    totient = (p - 1) * (q - 1)
    e = utils.genE(totient)
    d = utils.multi_inverse(e, totient)
    return e, d, n


m = "daru"
md = sha256(m)
e, d, n = genKey()
s = hex(pow(int(md, 16), e, n))[2:]

print('Key:', e, d, n)
print('keylen:', len(str(e)), len(str(d)), len(str(n)))
print('Hash:', md)
print('Encrypt:', s)

md = sha256(m)
s_v = hex(pow(int(s, 16), d, n))[2:]
v = hex(int(md, 16) % n)[2:]

print('Decrypt:', s_v)
print('Verifier:', v)
print('Tempered?', s_v != v)
