#This code is written based on: https://github.com/oreparaz/shoup/blob/master/shoup.py
#It follow set implementation for threshold RSA from 
# V. Shoup, "Practical Threshold Signatures", Eurocrypt 2000
# https://www.shoup.net/papers/thsig.pdf (Algorithm 2)
#Algorithm 2 supports more than k+1 malicious participants, where k represents the signature threshold

import random
import hashlib
from Crypto.PublicKey import RSA
import math
from statistics import variance, mean
from support import is_Prime, jacobi_symbol, lagrange, gcd_extended
import subprocess

urandom = random.SystemRandom()

class Shoup:
    def __init__(self):
        pass
    
    def setup(self, param, pem_file=None):
        self.validate_param(param)
        (sk_unshared, pk) = self.key_gen(param, self.prime_gen(param))
        sk_shared = self.deal(param, sk_unshared, pk)
        return (sk_shared, pk)

    def key_gen(self, param, primes):
        (p, q) = primes

        m = ((p-1)//2) * ((q-1)//2)

            # Shoup's protocol requires the RSA public exponent e be larger
            # than the number parties. Hence, the value e = 2**16 + 1 (F4)
            # should satisfy all reasonable needs. Hardcode it here.
        #e = 0x10001

        sk_unshared = {
            'p': p,
            'q': q,
            'd': pow(param['e'], -1, m),
            'm': m,
        }
        pk = {
            'n': p * q,
            'e': param['e'],
        }
        return (sk_unshared, pk)


    def validate_param(self, param):
        assert((param['number_parties_total'] - param['number_parties_corrupted'])
            >= param['number_parties_needed'])
        param['delta'] = math.factorial(param['number_parties_total'])

        assert(param['e'] > param['number_parties_needed'])
        assert(is_Prime(param['e']))

    def prime_gen(self, param):
        L = param['rsa_modulus_length_in_bits']
        p = self.openssl_generate_safe_prime(L / 2)
        q = self.openssl_generate_safe_prime(L / 2)
        while p == q:  # can happen w/ short primes (e.g., testing)
            # very small L can make this loop non-terminating
            q = self.openssl_generate_safe_prime(L / 2)
        return (p, q)

    def openssl_generate_safe_prime(self, bits):
        # shell out to openssl for safe prime generation
        cmd = "openssl prime -bits %d -checks 128 -generate -safe" % bits
        ret = int(subprocess.check_output(cmd.split(' ')))
        assert(self.is_sophie_germain(ret))
        assert(ret.bit_length() == bits)
        return int(ret)

    def is_sophie_germain(self, n):
        return is_Prime(n) and is_Prime((n-1)//2)

    def hash_message(self, message, pk, sk_shared):
        hashed = hashlib.sha256(message.encode('utf-8')).hexdigest()
        x_marked = int(hashed, base=16)
        x_marked_mod = x_marked

        jacobi_x = jacobi_symbol(x_marked, pk['n'])

        if jacobi_x == 1:
            x = x_marked % pk['n']
        else:
            x = (x_marked * pow(pk['u'], pk['e'], pk['n'])) % pk['n']

        return x

    def evaluate_poly(self, poly, point, m, delta):
        ret = 0
        for i in range(len(poly)):
            ret = (ret + ((poly[i] * (pow(point, i, m))) % m))
        return (ret * pow(delta, -1, m)) % m


    def split_shamir(self, secret, number_coeffs, number_shares, modulus, delta):
        a = [0] * number_coeffs
        a[0] = secret

        for i in range(1, number_coeffs):
            a[i] = self.urandom_num(modulus)
        s = [0] * number_shares
        for i in range(number_shares):
            s[i] = self.evaluate_poly(a, i+1, modulus, delta)
            # sweis adds here a random multiple of m
            # https://github.com/sweis/threshsig/blob/master/src/main/java/threshsig/Dealer.java#L165
        return s

    def deal(self, param, sk_unshared, pk):
        # Generate shares for the secret key by Shamir splitting
        # and shares of the verification key.
        s = self.split_shamir(secret=sk_unshared['d'],
                            number_coeffs=param['number_parties_needed'],
                            number_shares=param['number_parties_total'],
                            modulus=sk_unshared['m'], delta=param['delta'])

        # verification keys
        v_pre = self.urandom_num(pk['n'])
        assert(math.gcd(v_pre, pk['n']) == 1)
        v = pow(v_pre, 2, pk['n']) 

        u = self.compute_u(pk['n'])

        vs = [0] * param['number_parties_total']
        for i in range(len(vs)):
            vs[i] = pow(v, s[i], pk['n'])

        pk['v'] = v
        pk['u'] = u
        pk['vs'] = vs

        sk_shared = {
            's': s,
            'vs': vs,
        }
        return sk_shared

    def compute_u(self, n):
        u = self.urandom_num(n)
        match = False
        while match:
            u = self.urandom_num(n)
            if(math.gcd(u, n) == 1):
                jacobi = jacobi_symbol(u, n)

                if(jacobi == -1):
                    match = True
        return u

    def urandom_num(self, n):
        return urandom.randint(0, n-1)  # inclusive 0 and n-1

    def signature_shares(self, param, pk, sk_shared, message):
        xi = [0] * param['number_parties_total']
        for i in range(param['number_parties_total']):
            exponent = 2 * sk_shared['s'][i]
            xi[i] = pow(message, exponent, pk['n'])
        return xi

    def hash_transcript(self, **transcript):
        hexdigest = hashlib.sha256(str(transcript).encode('utf-8')).hexdigest()
        return int(hexdigest, base=16)

    def construct_proof(self, pk, sk, message, sigshare, id):
        xt = pow(message, 4, pk['n'])
        r = self.urandom_num(pk['n'])
                
        c = self.hash_transcript(v=pk['v'],
                                xt=xt,
                                vi=pk['vs'][id-1],
                                xi2=pow(sigshare, 2, pk['n']),
                                vp=pow(pk['v'], r, pk['n']),
                                xp=pow(xt, r, pk['n']))
                 
        z = (sk*c) + r
        proof = (z, c)

        return proof

    def verify_proof(self, pk, proof, message, sigshare, id):
        xt = pow(message, 4, pk['n'])
        z, c = proof

        vp1 = pow(pk['v'], z, pk['n'])
        vp2 = pow(pk['vs'][id-1], -c, pk['n'])

        xp1 = pow(xt, z, pk['n'])
        xp2 = pow(sigshare, -2*c, pk['n'])

        ver_c = self.hash_transcript(v=pk['v'],
                                    xt=xt,
                                    vi=pk['vs'][id-1],
                                    xi2=pow(sigshare, 2, pk['n']),
                                    vp= (vp1*vp2) % pk['n'],
                                    xp=(xp1*xp2) % pk['n'])

        if ver_c == c:
            return True
        else:
            return False

    def reconstruct_signature_shares(self, param, pk, sigshares, message, sk_shares):
        e = pk['e']
        delta = param['delta']
        e_prime = 4
        (gcd_e_eprime, bezout_a, bezout_b) = gcd_extended(e_prime, e)
        assert(gcd_e_eprime == 1)

        w = 1
        quorum = range(1, param['number_parties_needed']+1)
        for i in quorum:
            exponent = 2 * lagrange(quorum, 0, i, delta)
            part = pow(sigshares[i-1], exponent, pk['n'])
            w = (w * part) % pk['n']

        assert(pow(w, e, pk['n']) == pow(message, e_prime, pk['n']))

        p1 = pow(w, bezout_a, pk['n'])
        p2 = pow(message, bezout_b, pk['n'])
        signature_recombined = (p1*p2) % pk['n']

        assert((pow(signature_recombined, e, pk['n'])) == message)
        return signature_recombined

def test_shamir(param):
    shoup = Shoup()
    param['delta'] = math.factorial(param['number_parties_total'])
    # Test Shamir shares do not leak more than necessary.
    #
    # In a (n, k) secret sharing, any k-1 shares should be
    # independent of the secret. Here, k=2, which means
    # one piece is independent from the secret, but two
    # disclose it.
    #
    m = 7  # work in the small field F_7 (small field -> bias easier to detect)
    number_shares = 3  # number of pieces
    number_coeffs = 2  # poly of order 1
    number_samples = 10000
    for picked_shares in range(1, number_shares+1):
        c0s = []
        c1s = []
        for i in range(number_samples):
                # shares for secret 0
            s0 = shoup.split_shamir(0, number_coeffs, number_shares, m, param['delta'])
                # shares for secret 2
            s1 = shoup.split_shamir(2, number_coeffs, number_shares, m, param['delta'])
            c0 = 1
            c1 = 1
            for j in range(picked_shares):
                c0 = c0 * s0[j]
                c1 = c1 * s1[j]
            c0s.append(float(c0))
            c1s.append(float(c1))

        expected_leak = False
        if picked_shares >= number_coeffs:
            expected_leak = True
        welch_num = (mean(c0s) - mean(c1s))
        welch_den = math.sqrt((variance(c0s)/len(c0s)) + (variance(c1s)/len(c1s)))
        welch = welch_num / welch_den
        leak = abs(welch) > 5
        assert(leak == expected_leak)

def round1(param, pk, sk_shared, message_to_sign, shoup):
    sigshares = shoup.signature_shares(param, pk, sk_shared, message_to_sign)
    proof = shoup.construct_proof(pk, sk_shared['s'][0], message_to_sign, sigshares[0], 1)
    
    correct = shoup.verify_proof(pk, proof, message_to_sign, sigshares[0], 1)

    print("Signature check", correct)
    return (sigshares)

def round2(param, pk, sk_shared, message_to_sign, sigshares, shoup):
    signature_recombined = shoup.reconstruct_signature_shares(param,
                                                        pk,
                                                        sigshares,
                                                        message_to_sign, sk_shared)
    return signature_recombined

def test_roundtrip(message):
    shoup = Shoup()
    (sk_shared, pk) = shoup.setup(param)

    print(sk_shared)
    print(pk)

    message_to_sign = shoup.hash_message(message, pk, sk_shared)
    (sigshares) =round1(param, pk, sk_shared, message_to_sign, shoup)
    combined_signature = round2(param, pk, sk_shared, message_to_sign, sigshares, shoup)

    print("combined signature", combined_signature)

def test_cheat(message):
    shoup = Shoup()
    (sk_shared, pk) = shoup.setup(param)
        #message_to_sign = random_message(pk)
    message_to_sign = shoup.hash_message(message, pk, sk_shared)
    (sigshares, proofs) = round1(param, pk, sk_shared, message_to_sign)
    proofs[0] = (proofs[0][0], proofs[0][1]+1)  # cheat
    detected_corruption = False
    try:
        round2(param, pk, sk_shared, message_to_sign, sigshares, proofs)
    except AssertionError:
        detected_corruption = True
    assert(detected_corruption)

param = {
    # RSA modulus length, in bits.
    # A toy value suitable for testing is, e.g., 100.
    # A more realistic value is, e.g., 3072
    'rsa_modulus_length_in_bits': 100,
    # Number of signature shares needed to obtain a signature.
    # This is k in the paper.
    'number_parties_needed': 6,
    # Number of players engaging in the protocol. This is l in the paper.
    'number_parties_total': 10,
    # This is t in the paper. max k-1. Currently unused in this code.
    'number_parties_corrupted': 1,
    "e": 0x10001,
}

test_roundtrip("Accept")
#test_shamir(param)