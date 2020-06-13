from __future__ import division
from __future__ import print_function
import socket
from random import randint
from random import seed
from random import randint
import hashlib
import Crypto.Util.number
import sys
from Crypto import Random
import random
from numpy.polynomial.polynomial import Polynomial as Poly
import numpy.polynomial.polynomial as polynomial
import functools
import random 
from math import pow
import pickle

_RINT = functools.partial(random.SystemRandom().randint, 0)

def gcd(a, b): 
	if a < b: 
		return gcd(b, a) 
	elif a % b == 0: 
		return b; 
	else: 
		return gcd(b, a % b) 

def gen_key(q): 

	key = random.randint(pow(10, 20), q) 
	while gcd(q, key) != 1: 
		key = random.randint(pow(10, 20), q) 

	return key 

def power(a, b, c): 
	x = 1
	y = a 

	while b > 0: 
		if b % 2 == 0: 
			x = (x * y) % c; 
		y = (y * y) % c 
		b = int(b / 2) 

	return x % c 

def encrypt(msg, q, h, g):
	en_msg = [] 

	k = gen_key(q)
	s = power(h, k, q) 
	p = power(g, k, q) 
	
	for i in range(0, len(msg)): 
		en_msg.append(msg[i]) 

	for i in range(0, len(en_msg)): 
		en_msg[i] = s * ord(en_msg[i]) 

	return en_msg, p 

def convert_string_asciisum(m):
    asc = [ord(c) for c in m]
    return sum(asc)

def calculate_z(g,q):
    temp = randint(1,q-1)
    z = (g**temp)%q
    return z

def hash_function(x1,x2,g,z,q):
    hash_val = ((g**x1)%q * (z**x2)%q)%q
    return hash_val

def loop_exponent(exponent, nr, r, p):
    while(nr != 1):
        nr = (nr*r)%p
        exponent= exponent+1
    return exponent

def generating_x(g,q):
    x = randint(1,g-1)
    y = (g**x)%q
    return y,x

def loop_gen(nr, exponent, r, p, g):
    exponent = loop_exponent(exponent, nr, r, p)
    if(exponent == p-1 and exponent != None):
        g.append(r)

def generator(p):
    g = []
    for i in range(1,p):
        r = i
        exponent = 1
        nr = r%p
        loop_gen(nr, exponent, r, p, g)
    return random.choice(g)

def choosing_p(n):
    q = Crypto.Util.number.getPrime(n, randfunc=Random.get_random_bytes)
    return q


def digital_signature(m,q,g,x,z):
    M = convert_string_asciisum(m)
    k = 13 #randint(1, q-1)
    r = (g**k)%q
    e = (hash_function(r,M, g,z,q))
    s = (k-(x*e))%(q-1)
    return s,e


def _eval_at(poly, x, prime):
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum

def make_random_shares(k, n, prime):
    if k > n:
        raise ValueError("Pool secret would be irrecoverable.")
    poly = [_RINT(prime - 1) for i in range(k)]
    points = [(i, _eval_at(poly, i, prime))
              for i in range(1, n + 1)]
    return poly[0], points

def _extended_gcd(a, b):
    x = 0
    last_x = 1
    y = 1
    last_y = 0
    while b != 0:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y
    return last_x, last_y

def _divmod(num, den, p):
    inv, _ = _extended_gcd(den, p)
    return num * inv

def _lagrange_interpolate(x, x_s, y_s, p):
    k = len(x_s)
    assert k == len(set(x_s)),"points must be distinct"
    def PI(vals):
        accum = 1
        for v in vals:
            accum *= v
        return accum
    nums = []  # avoid inexact division
    dens = []
    for i in range(k):
        others = list(x_s)
        cur = others.pop(i)
        nums.append(PI(x - o for o in others))
        dens.append(PI(cur - o for o in others))
    den = PI(dens)
    num = sum([_divmod(nums[i] * den * y_s[i] % p, dens[i], p)
               for i in range(k)])
    return (_divmod(num, den, p) + p) % p

if(__name__=='__main__'):
    print('Client Started')
    s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    host1 = socket.gethostname()                           
    port1 = 12345
    s1.connect((host1, port1))

    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    host2 = socket.gethostname()                           
    port2 = 12346
    s2.connect((host2, port2))

    s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    host3 = socket.gethostname()                           
    port3 = 12347
    s3.connect((host3, port3))

    s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    host4 = socket.gethostname()                           
    port4 = 12348
    s4.connect((host4, port4))

    s5 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    host5 = socket.gethostname()                           
    port5 = 12349
    s5.connect((host5, port5))

    s6 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    host6 = socket.gethostname()                           
    port6 = 12350
    s6.connect((host6, port6))
    
    q = random.randint(pow(10, 20), pow(10, 50)) 
    g = random.randint(2, q)
    #print('q ',q)
    #print('g ',g)

    s1.send(str(q).encode())
    s1.send(str(g).encode())

    h = int(s1.recv(1024).decode())
    #print('h ',h)

    cl_S = 1234
    cl_n = 6
    cl_k = 3
    cl_p = choosing_p(5)
    cl_g = generator(cl_p)
    cl_z = calculate_z(cl_g, cl_p)
    cl_y,cl_x = generating_x(cl_g,cl_p)

    pub_info = [cl_g,cl_y,cl_p,cl_z]
    public_info = pickle.dumps(pub_info)

    s1.send(public_info)
    #print(pub_info)

    secret, points = make_random_shares(cl_k,cl_n,cl_p)

    sending_mesage = []

    #print('1')
    msg = ''
    sign, hash_ = digital_signature(str(points[0][1]),cl_p,cl_g,cl_x,cl_z)
    msg = str(points[0]) + '@#'
    msg = msg+str(sign)+'@#'
    msg = msg+str(hash_)
    en_msg, p = encrypt(msg, q, h, g)
    enc_msg = pickle.dumps(en_msg)
    s1.send(enc_msg)
    s1.send(str(p).encode())

    #print('2')
    msg = ''
    sign, hash_ = digital_signature(str(points[1][1]),cl_p,cl_g,cl_x,cl_z)
    msg = str(points[1]) + '@#'
    msg = msg+str(sign)+'@#'
    msg = msg+str(hash_)
    en_msg, p = encrypt(msg, q, h, g)
    enc_msg = pickle.dumps(en_msg)
    s2.send(enc_msg)
    p = 11111111111111111111111111111111111111111111111111
    s2.send(str(p).encode())

    #print('3')
    msg = ''
    sign, hash_ = digital_signature(str(points[2][1]),cl_p,cl_g,cl_x,cl_z)
    msg = str(points[2]) + '@#'
    msg = msg+str(sign)+'@#'
    msg = msg+str(hash_)
    en_msg, p = encrypt(msg, q, h, g)
    enc_msg = pickle.dumps(en_msg)
    s3.send(enc_msg)
    s3.send(str(p).encode())

    #print('4')
    msg = ''
    sign, hash_ = digital_signature(str(points[3][1]),cl_p,cl_g,cl_x,cl_z)
    msg = str(points[3]) + '@#'
    msg = msg+str(sign)+'@#'
    msg = msg+str(hash_)
    en_msg, p = encrypt(msg, q, h, g)
    enc_msg = pickle.dumps(en_msg)
    s4.send(enc_msg)
    #print('4p ',p)
    p = 11111111111111111111111111111111111111111111111111
    s4.send(str(p).encode())

    #print('5')
    msg = ''
    sign, hash_ = digital_signature(str(points[4][1]),cl_p,cl_g,cl_x,cl_z)
    msg = str(points[4]) + '@#'
    msg = msg+str(sign)+'@#'
    msg = msg+str(hash_)
    en_msg, p = encrypt(msg, q, h, g)
    enc_msg = pickle.dumps(en_msg)
    s5.send(enc_msg)
    s5.send(str(p).encode())

    #print('6')
    msg = ''
    sign, hash_ = digital_signature(str(points[5][1]),cl_p,cl_g,cl_x,cl_z)
    msg = str(points[5]) + '@#'
    msg = msg+str(sign)+'@#'
    msg = msg+str(hash_)
    en_msg, p = encrypt(msg, q, h, g)
    enc_msg = pickle.dumps(en_msg)
    s6.send(enc_msg)
    s6.send(str(p).encode())

    print('Secret in sender ',secret)