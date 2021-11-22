from random import getrandbits, randrange


def gcd(a, b):
    while b > 0:
        a, b = b, a % b
    return a


def lcm(a, b):
    return a * b // gcd(a, b)


def is_prime(n, k=128):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2

    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True


def genPrime(length=1024):
    while True:
        p = getrandbits(length)
        p |= (1 << length - 1) | 1
        if is_prime(p, 128):
            return p


def is_square(n):
    if n < 0:
        return False
    prev = n
    x = n // 2
    while x * x != n:
        x = (x + (n // x)) // 2
        if x >= prev:
            return False
        prev = x
    return True


def sqrtmod(a, p):
    a = a % p
    res = []
    for x in range(2, p):
        if (x * x) % p == a:
            res.append(x)
    return res


def genECPoints(a, b, p, start=0, n=20):
    x = start
    count = 0
    points = []
    while True:
        f = (pow(x, 3) + a * x + b) % p
        if f == 0:
            _p = (x, f)
            points.append(_p)
            count += 1

        fs = sqrtmod(f, p)
        for i in fs:
            _p = (x, i)
            points.append(_p)
            count += 1

        if count >= n:
            break

        x += 1
    return points


def multi_inverse(e, totient):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_totient = totient

    while e > 0:
        temp1 = temp_totient//e
        temp2 = temp_totient - temp1 * e
        temp_totient = e
        e = temp2

        x = x2 - temp1 * x1
        y = d - temp1 * y1

        x2 = x1
        x1 = x
        d = y1
        y1 = y

    if temp_totient == 1:
        return d + totient


def genE(totient):
    while (True):
        e = randrange(2, totient)
        if (gcd(e, totient) == 1):
            return e


def genPrimeRange(start, end):
    while (True):
        res = randrange(start, end)
        if (is_prime(res)):
            return res


def str_to_int(m):
    _m = ""
    for c in m:
        i_c = str(ord(c))
        i_c = "0" * (3 - len(i_c)) + i_c
        _m += i_c
    return int(_m)


def int_to_str(m):
    _m = str(m)
    _m = "0" * ((3 - (len(_m) % 3)) if len(_m) % 3 > 0 else 0) + _m
    x = ""
    for i in range(0, len(_m), 3):
        c = chr(int(_m[i:i+3]))
        x += c
    return x


def bin_to_int(m):
    _m = ""
    for b in m:
        i_b = str(int(b))
        i_b = "0" * (3 - len(i_b)) + i_b
        _m += i_b
    return int(_m)


def int_to_bin(m):
    _m = str(m)
    _m = "0" * ((3 - (len(_m) % 3)) if len(_m) % 3 > 0 else 0) + _m
    x = bytes()
    for i in range(0, len(_m), 3):
        b = int(_m[i:i+3])
        b = b.to_bytes(1, 'big')
        x += b
    return x
