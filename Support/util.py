import random
import hashlib

class Shares():
   def __init__(self, index, index_signiture, share, share_signature):
       self.index = index
       self.index_signiture = index_signiture
       self.share = share
       self.share_signature = share_signature

def is_Prime(n):    
    """
    Miller-Rabin primality test.
        
    A return value of False means n is certainly not prime. A return value of
    True means n is very likely a prime.
    """
    if n!=int(n):
        return False
    n=int(n)
    #Miller-Rabin test for prime
    if n==0 or n==1 or n==4 or n==6 or n==8 or n==9:
        return False
        
    if n==2 or n==3 or n==5 or n==7:
        return True
    s = 0
    d = n-1
    while d%2==0:
        d>>=1
        s+=1
    assert(2**s * d == n-1)

    def trial_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2**i * d, n) == n-1:
                return False
        return True  
        
    for i in range(8):#number of trials 
        a = random.randrange(2, n)
        if trial_composite(a):
            return False
        
    return True

#Based on the Jacobi symbol pseudocode from Cryptography made Simple by Nigel Smart 
#    (algorithm 1.4 doi:10.1007/978-3-319-21936-3)
def jacobi_symbol(a, n):
    if (n <= 0) or ((n % 2) == 0):
        return 0
    j = 1

    if a < 0:
        a = -a
        if n % 4 == 3:
            j = -j
        
    while a != 0:
        while ((a % 2) == 0):
            a = a//2
            if ((n % 8) == 3) or ((n % 8) == 5):
                j = -j    
        temp = a
        a = n
        n = temp

        if ((a % 4) == 3) and ((n % 4) == 3):
            j = -j

        a = a % n

    if n == 1:
        return j
    return 0

def lagrange(S, i, j, delta):
    ret = delta
    for j_prime in S:
        if j_prime != j:
            ret = (ret * (i - j_prime)) // (j - j_prime)
    return ret

#Based on https://www.geeksforgeeks.org/python-program-for-basic-and-extended-euclidean-algorithms-2/
def gcd_extended(a, b): 
    # Base Case 
    if a == 0 :  
        return b,0,1
                
    gcd,x1,y1 = gcd_extended(b%a, a) 
        
    x = y1 - (b//a) * x1 
    y = x1 
        
    return gcd,x,y

def hash_transcript(**transcript):
        hexdigest = hashlib.sha256(str(transcript).encode('utf-8')).hexdigest()
        return int(hexdigest, base=16)

def hash_message(message, pk):
        hashed = hashlib.sha256(message.encode('utf-8')).hexdigest()
        x_marked = int(hashed, base=16)
        x_marked_mod = x_marked

        jacobi_x = jacobi_symbol(x_marked, pk['n'])

        if jacobi_x == 1:
            x = x_marked % pk['n']
        else:
            x = (x_marked * pow(pk['u'], pk['e'], pk['n'])) % pk['n']

        return x

COUNT = [50]
#got it from https://www.geeksforgeeks.org/print-binary-tree-2-dimensions/ used for debugging
def print2DUtil(root, space) :
    if (root == None) :
        return

    space += COUNT[0]
    print2DUtil(root.right, space) 

    print() 
    for i in range(COUNT[0], space):
        print(end = " ") 
    print(root.data) 

    print2DUtil(root.left, space)
        
def print2D(root) :
    print2DUtil(root, 0) 

def append_to_file(filename, string):
    f = open(filename, "a")
    if type(string) is str:
        f.write(string + "\n")
    else:
        f.write(str(string) + "\n")
    f.close()
