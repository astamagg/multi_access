from typing import Tuple
from os import urandom
from Crypto.Protocol.SecretSharing import Shamir

#Uses the pycryptodome library for the secret sharing https://www.pycryptodome.org/en/v3.6.1/src/protocol/ss.html
#Secret is accociated under the field of 2^128 and the shares are 16 bytes. As we are using AES 256 we need a key of 32 bytes. 
#   We obtain this by splitting the secret in two and performing two Shamir secret sharings.
class ShamirSecretSharing:
    #receives a list of shares and reconstructs the encryption key using them
    @staticmethod
    def reconstructSecret(shares: Tuple[bytes]) -> bytes:
        first_shares = list()
        second_shares = list()

        for i, share in enumerate(shares):
            index = share.index
            full_share = share.share
            
            first_partial_share = full_share[:16]
            second_partial_share = full_share[16:]

            first_shares.append((index, first_partial_share))
            second_shares.append((index, second_partial_share))

        combine_first = Shamir.combine(first_shares)
        combine_second = Shamir.combine(second_shares)

        reconstructed_key = combine_first + combine_second

        return reconstructed_key
        
    #Computes shares for so that t-out-of-n shares are needed in order to reconstruct the secret.
    #The secret is the encryption key
    @staticmethod
    def computeSecrets(t: int, n: int, secret:bytes) -> Tuple[int, bytes]:
        first_part = secret[:16]
        second_part = secret[16:]

        first_shares = Shamir.split(t, n, first_part)
        second_shares = Shamir.split(t,n, second_part)
        shares = list()

        for i in range(len(first_shares)):
            j, first_partial_share = first_shares[i]
            k, second_partial_share = second_shares[i]
            share = first_partial_share + second_partial_share
            shares.append((j, share))

        return shares