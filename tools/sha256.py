def print_bin(bins, w=8, l=8):
    r = len(bins) % w
    x = 0
    for i in range(len(bins)//w):
        if x < (l - 1):
            print(bins[i * w: (i+1) * w], end=" ")
            x += 1
        else:
            print(bins[i * w: (i+1) * w])
            x = 0

    print(bins[(i + 1) * w: (i + 1) * w + r])


def rightrotate(bins, n):
    return bins[len(bins) - n:] + bins[:len(bins) - n]


def rightshift(bins, n):
    return '0' * n + bins[:len(bins) - n]


def bin_xor(bins, bin_o):
    return ''.join('0' if bins[i] == bin_o[i] else '1' for i in range(len(bins)))


def bin_and(bins, bin_o):
    return ''.join('1' if bins[i] == '1' and bin_o[i] == '1' else '0' for i in range(len(bins)))


def bin_not(bins):
    return ''.join('1' if bins[i] == '0' else '0' for i in range(len(bins)))


def hex_to_bin(_hex, w=32):
    b = bin(_hex)[2:]
    return '0' * (w - len(b)) + b


def bin_to_hex(_bin, w=8):
    h = format(int(_bin, 2), 'x')
    return '0' * (w - len(h)) + h


def bin_sum(bins, bin_o):
    r = 0
    retval = ''
    for i in range(len(bins)-1, -1, -1):
        s = int(bins[i]) + int(bin_o[i]) + r
        if s > 1:
            r = 1
            retval = str(s-2) + retval
        else:
            r = 0
            retval = str(s) + retval
    return retval


def sha256(text):
    # step 1
    str_test = text
    bin_test = ''.join(format(ord(i), '08b') for i in str_test)
    bins = bin_test
    bins += '1'
    bins += '0' * (512 - (len(bins) % 512) - 64)
    len_bin_test = format(len(bin_test), '08b')
    bins += '0' * (64 - len(len_bin_test)) + len_bin_test

    # step 2
    H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

    # step 3
    K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    h_o = [hex_to_bin(x) for x in H]
    # step 4
    for z in range(len(bins) // 512):

        # step 5
        w = bins[z * 512: (z+1) * 512]
        w += "0" * 32 * 48

        for i in range(16, 64):
            s0_1 = rightrotate(w[(i-15) * 32: (i+1-15) * 32], 7)
            s0_2 = rightrotate(w[(i-15) * 32: (i+1-15) * 32], 18)
            s0_3 = rightshift(w[(i-15) * 32: (i+1-15) * 32], 3)

            s0 = bin_xor(bin_xor(s0_1, s0_2), s0_3)

            s1_1 = rightrotate(w[(i-2) * 32: (i+1-2) * 32], 17)
            s1_2 = rightrotate(w[(i-2) * 32: (i+1-2) * 32], 19)
            s1_3 = rightshift(w[(i-2) * 32: (i+1-2) * 32], 10)

            s1 = bin_xor(bin_xor(s1_1, s1_2), s1_3)

            w_o = bin_sum(bin_sum(
                bin_sum(w[(i-16) * 32: (i+1-16) * 32], s0), w[(i-7) * 32: (i+1-7) * 32]), s1)
            w = w[: i * 32] + w_o + w[(i+1)*32:]

        temp_h = [x for x in h_o]

        for i in range(0, 64):
            s1_1 = rightrotate(temp_h[4], 6)
            s1_2 = rightrotate(temp_h[4], 11)
            s1_3 = rightrotate(temp_h[4], 25)
            s1 = bin_xor(bin_xor(s1_1, s1_2), s1_3)

            ch = bin_xor(bin_and(temp_h[4], temp_h[5]),
                         bin_and(bin_not(temp_h[4]), temp_h[6]))
            temp1 = bin_sum(bin_sum(bin_sum(bin_sum(temp_h[7], s1), ch),
                            hex_to_bin(K[i])), w[i*32:(i+1) * 32])

            s0_1 = rightrotate(temp_h[0], 2)
            s0_2 = rightrotate(temp_h[0], 13)
            s0_3 = rightrotate(temp_h[0], 22)
            s0 = bin_xor(bin_xor(s0_1, s0_2), s0_3)

            maj = bin_xor(bin_xor(bin_and(temp_h[0], temp_h[1]), bin_and(
                temp_h[0], temp_h[2])), bin_and(temp_h[1], temp_h[2]))
            temp2 = bin_sum(s0, maj)

            temp_h[7] = temp_h[6]
            temp_h[6] = temp_h[5]
            temp_h[5] = temp_h[4]
            temp_h[4] = bin_sum(temp_h[3], temp1)
            temp_h[3] = temp_h[2]
            temp_h[2] = temp_h[1]
            temp_h[1] = temp_h[0]
            temp_h[0] = bin_sum(temp1, temp2)

        h_o = [bin_sum(h_o[i], temp_h[i]) for i in range(len(h_o))]

    digest = ''.join([bin_to_hex(x) for x in h_o])
    return digest
