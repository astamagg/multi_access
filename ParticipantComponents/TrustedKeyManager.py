from os import urandom
from Support.protocols import ShamirSecretSharing
from typing import Tuple
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA512
import sys
from ParticipantComponents.WorkerOperator import WorkerOperator
from Support.util import is_Prime, jacobi_symbol, Shares
import subprocess
import math
import time
import secrets

class TrustedKeyManager:
    def __init__(self, id, owners, operators):
        self.id = id
        self.owners = owners
        self.operators = operators
        self.urandom = secrets.SystemRandom()

    #Create the secret signing key for encryption
    def generate_owner_keys(self, threshold: int, total: int) -> Tuple[int, bytes]:
        encryption_key = urandom(32)
        shares = ShamirSecretSharing.computeSecrets(threshold, total, encryption_key)

        return shares

    #Generate and store a new set of RSA keys for signing
    def generate_rsa_keys(self, key_length: int):
        rsa_key = RSA.generate(key_length)
        f = open('TKM_keys/private_key.pem','wb')
        f.write(rsa_key.export_key('PEM'))
        f.close()

        f_out = open('TKM_keys/public_key.pem', 'wb')
        f_out.write(rsa_key.publickey().export_key())
        f_out.close()

    #split the key among the owners using Shamir secret sharing
    #@ray.method(num_returns = 1)
    def share_secrets(self, threshold, total, params, timed = False, testing = False):
        if timed:
            start = time.time()
            self.generate_rsa_keys(2048)
            shares = self.generate_owner_keys(threshold, total)
            signed_shares = self.generate_signature(shares)
            (sk_shares, pk) = self.setup_shoup(params)
            end = time.time()
            time_result = end - start

        else:
            shares = self.generate_owner_keys(threshold, total)
            signed_shares = self.generate_signature(shares)
            (sk_shares, pk) = self.setup_shoup(params)
            time_result = None

        total_count = 0

        for i, owner in enumerate(self.owners.values()):
            owner.receive_share(signed_shares[i], sk_shares[i], pk)

        for j, operator in enumerate(self.operators.values()):
            operator.receive_signing_params(pk, params)

        if testing:
            return signed_shares, sk_shares, pk, time_result

    # Using RSA as it is better suited for verification of signatures as verification is faster, Cryptography made simple page 336
    # https://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_pss.html method documentation
    # Size does not matter
    # Going to use PKCS#1 RSA as it is probabilistic
    def generate_signature(self, shares: Tuple[int, bytes]):
        f = open('TKM_keys/private_key.pem','r')
        key = RSA.import_key(f.read())
        f.close()

        print("size of encryption key: {}".format(key.size_in_bytes()))

        signed_shares = []

        for share in shares:
            i, share_value = share
            
            h_i = SHA512.new(str(i).encode('utf-8'))
            h_share = SHA512.new(share_value)
            signature_i = pss.new(key).sign(h_i)
            signature_share = pss.new(key).sign(h_share)

            signed_share = Shares(i, signature_i, share_value, signature_share)
            signed_shares.append(signed_share)
        return signed_shares

    def evaluate_poly(self, poly, point, m, delta):
        ret = 0
        for i in range(len(poly)):
            ret = (ret + ((poly[i] * (pow(point, i, m))) % m))
        return (ret * pow(delta, -1, m)) % m

    def split_shamir(self, secret, number_coeffs, number_shares, modulus, delta):
        a = [0] * number_coeffs
        a[0] = secret
        
        shares = []
        for i in range(1, number_coeffs):
            a[i] = self.urandom_num(modulus)
        s = [0] * number_shares
        for i in range(number_shares):
            s[i] = self.evaluate_poly(a, i+1, modulus, delta)
            shares.append((i+1, s[i]))
            # sweis adds here a random multiple of m
            # https://github.com/sweis/threshsig/blob/master/src/main/java/threshsig/Dealer.java#L165
        return shares


    def setup_shoup(self, param, pem_file=None):
        self.validate_param(param)
        (sk_unshared, pk) = self.key_gen_shoup(param, self.prime_gen(param))
        sk_shared = self.deal_shoup(param, sk_unshared, pk)
        return (sk_shared, pk)

    def validate_param(self, param):
        assert((param['number_parties_total'] - param['number_parties_corrupted'])
            >= param['number_parties_needed'])
        param['delta'] = math.factorial(param['number_parties_total'])

        assert(param['e'] > param['number_parties_needed'])
        assert(is_Prime(param['e']))

    def key_gen_shoup(self, param, primes):
        (p, q) = primes

        m = ((p-1)//2) * ((q-1)//2)

            # Shoup's protocol requires the RSA public exponent e be larger
            # than the number parties. Hence, the value e = 2**16 + 1 (F4)
            # should satisfy all reasonable needs. Hardcode it here.
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

    def urandom_num(self, n):
        return self.urandom.randint(0, n-1)  # inclusive 0 and n-1

    def deal_shoup(self, param, sk_unshared, pk):
        # Generate shares for the secret key by Shamir splitting
        # and shares of the verification key.
        s = self.split_shamir(secret=sk_unshared['d'],
                            number_coeffs=param['number_parties_needed'],
                            number_shares=param['number_parties_total'],
                            modulus=sk_unshared['m'], delta=param['delta'])

        v_pre = self.urandom_num(pk['n'])
        assert(math.gcd(v_pre, pk['n']) == 1)
        v = pow(v_pre, 2, pk['n']) 

        u = self.compute_u(pk['n'])

        vs = [0] * param['number_parties_total']
        for i in range(len(vs)):
            vs[i] = pow(v, s[i][1], pk['n'])

        pk['v'] = v
        pk['u'] = u
        pk['vs'] = vs

        return s

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