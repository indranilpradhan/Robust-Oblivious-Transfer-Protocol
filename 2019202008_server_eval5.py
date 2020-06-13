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

def decrypt(en_msg, p, key, q): 
	dr_msg = [] 
	h = power(p, key, q) 
	for i in range(0, len(en_msg)): 
		dr_msg.append(chr(int(en_msg[i]/h))) 
		
	return dr_msg 

def convert_string_asciisum(m):
    asc = [ord(c) for c in m]
    return sum(asc)

def hash_function(x1,x2,g,z,q):
    hash_val = ((g**x1)%q * (z**x2)%q)%q
    return hash_val

def verifier(g,y,q,m,s,e,z):
    M = convert_string_asciisum(m)
    h_s = (g**s)%q
    h_y = (y**e)%q
    rv = (h_s*h_y)%q
    ev = (hash_function(rv,M,g,z,q))
    return ev

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

def recover_secret(points, prime):
    if len(points) < 2:
        raise ValueError("need at least two shares")
    #print(*points)
    x_s, y_s = zip(*points)
    return _lagrange_interpolate(0, x_s, y_s, prime)

def receiver(n,k,sending_mesage,p,g,y,z):
    count = 0
    new_message = []
    for i in sending_mesage:
        ev = verifier(g,y,p,str(i[0][1]),i[1],i[2],z)
        if(int(i[2]) != int(i[2])):
            count = count+1
            continue
        new_message.append(i[0])
    if(count > n-k):
        print("Unable to recover the data")
    else:
        print("The secret in receiver is ",recover_secret(new_message,p))

if(__name__ == '__main__'):
    print('Server started')
    serversocket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    host1 = socket.gethostname()                           
    port1 = 12345                                           
    serversocket1.bind((host1, port1))                                  
    serversocket1.listen(5) 

    serversocket2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    host2 = socket.gethostname()                           
    port2 = 12346                                           
    serversocket2.bind((host2, port2))                                  
    serversocket2.listen(5) 

    serversocket3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    host3 = socket.gethostname()                           
    port3 = 12347                                           
    serversocket3.bind((host3, port3))                                  
    serversocket3.listen(5)

    serversocket4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    host4 = socket.gethostname()                           
    port4 = 12348                                           
    serversocket4.bind((host4, port4))                                  
    serversocket4.listen(5)

    serversocket5 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    host5 = socket.gethostname()                           
    port5 = 12349                                           
    serversocket5.bind((host5, port5))                                  
    serversocket5.listen(5)

    serversocket6 = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    host6 = socket.gethostname()                           
    port6 = 12350                                           
    serversocket6.bind((host6, port6))                                  
    serversocket6.listen(5)

    #while True:
    clientsocket1,addr1 = serversocket1.accept()
    clientsocket2,addr2 = serversocket2.accept()
    clientsocket3,addr3 = serversocket3.accept()
    clientsocket4,addr4 = serversocket4.accept()
    clientsocket5,addr5 = serversocket5.accept()
    clientsocket6,addr6 = serversocket6.accept()
    #print('accepted')
    q = int(clientsocket1.recv(1024).decode())
    g = int(clientsocket1.recv(1024).decode())
    # print('q ',q)
    # print('g ',g)

    key = gen_key(q)
    h = power(g, key, q)
    # print('key ', key)
    # print('h ', h)

    clientsocket1.send(str(h).encode())

    pub_info = clientsocket1.recv(4096)
    public_info = pickle.loads(pub_info)
    # print('pubic_info ',public_info)

    n = 6
    k = 3
    sv_g = public_info[0]
    sv_y = public_info[1]
    sv_p = public_info[2]
    sv_z = public_info[3]

    received_mesage = []
        
    # print('1')
    try:
        enc_msg = clientsocket1.recv(4096)
        en_msg = pickle.loads(enc_msg)
        p = int(clientsocket1.recv(1024).decode())
        dr_msg = decrypt(en_msg, p, key, q) 
        dmsg = ''.join(dr_msg)
        t_temp = dmsg.split('@#')
        temp = []
        temp.append(eval(t_temp[0]))
        temp.append(int(t_temp[1]))
        temp.append(int(t_temp[2]))
        received_mesage.append(temp)
    except:
        pass

    # print('2')
    try:
        enc_msg = clientsocket2.recv(4096)
        en_msg = pickle.loads(enc_msg)
        p = int(clientsocket2.recv(1024).decode())
        dr_msg = decrypt(en_msg, p, key, q) 
        dmsg = ''.join(dr_msg)
        t_temp = dmsg.split('@#')
        temp = []
        temp.append(eval(t_temp[0]))
        temp.append(int(t_temp[1]))
        temp.append(int(t_temp[2]))
        received_mesage.append(temp)
    except:
        pass

    # print('3')
    try:
        enc_msg = clientsocket3.recv(4096)
        en_msg = pickle.loads(enc_msg)
        p = int(clientsocket3.recv(1024).decode())
        dr_msg = decrypt(en_msg, p, key, q) 
        dmsg = ''.join(dr_msg)
        t_temp = dmsg.split('@#')
        temp = []
        temp.append(eval(t_temp[0]))
        temp.append(int(t_temp[1]))
        temp.append(int(t_temp[2]))
        received_mesage.append(temp)
    except:
        pass

    # print('4')
    try:
        enc_msg = clientsocket4.recv(4096)
        en_msg = pickle.loads(enc_msg)
        p = int(clientsocket4.recv(1024).decode())
        dr_msg = decrypt(en_msg, p, key, q) 
        dmsg = ''.join(dr_msg)
        t_temp = dmsg.split('@#')
        temp = []
        temp.append(eval(t_temp[0]))
        temp.append(int(t_temp[1]))
        temp.append(int(t_temp[2]))
        received_mesage.append(temp)
    except:
        pass

    # print('5')
    try:
        enc_msg = clientsocket5.recv(4096)
        en_msg = pickle.loads(enc_msg)
        p = int(clientsocket5.recv(1024).decode())
        dr_msg = decrypt(en_msg, p, key, q) 
        dmsg = ''.join(dr_msg)
        t_temp = dmsg.split('@#')
        temp = []
        temp.append(eval(t_temp[0]))
        temp.append(int(t_temp[1]))
        temp.append(int(t_temp[2]))
        received_mesage.append(temp)
    except:
        pass

    # print('6')
    try:
        enc_msg = clientsocket6.recv(4096)
        en_msg = pickle.loads(enc_msg)
        p = int(clientsocket6.recv(1024).decode())
        dr_msg = decrypt(en_msg, p, key, q) 
        dmsg = ''.join(dr_msg)
        t_temp = dmsg.split('@#')
        temp = []
        temp.append(eval(t_temp[0]))
        temp.append(int(t_temp[1]))
        temp.append(int(t_temp[2]))
        received_mesage.append(temp)
    except:
        pass

    receiver(n,k,received_mesage,sv_p,sv_g,sv_y,sv_z)

    clientsocket1.close()
    clientsocket2.close()
    clientsocket3.close()
    clientsocket4.close()
    clientsocket5.close()
    clientsocket6.close()
