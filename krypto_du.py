import math

def GenerateCipher():    
    P1 = [22, 13, 10, 18, 3, 1, 23, 20, 15, 2, 0, 21, 11, 12, 19, 16, 8, 14, 4, 5, 17, 6, 9, 7]
    P2 = [2, 1, 6, 21, 23, 13, 18, 5, 14, 4, 9, 8, 20, 19, 7, 10, 16, 17, 22, 11, 0, 12, 3, 15]
    S = [24, 19, 43, 35, 12, 29, 40, 21, 33, 58, 48, 59, 22, 60, 32, 54, 17, 6, 56, 52, 37, 44, 10, 50, 15, 49, 30, 61, 13, 18, 46, 39, 16, 31, 28, 8, 53, 7, 51, 47, 41, 38, 26, 36, 57, 27, 0, 1, 62, 2, 63, 14, 23, 20, 3, 4, 45, 5, 11, 34, 55, 42, 9, 25]
    return [S, P1, P2]

def hex2bin(hexstring):
   bin = {'0':[0,0,0,0], '1':[0,0,0,1], '2':[0,0,1,0], '3':[0,0,1,1], '4':[0,1,0,0], '5':[0,1,0,1], '6':[0,1,1,0], '7':[0,1,1,1], '8':[1,0,0,0], '9':[1,0,0,1], 'a':[1,0,1,0], 'b':[1,0,1,1], 'c':[1,1,0,0], 'd':[1,1,0,1], 'e':[1,1,1,0], 'f':[1,1,1,1]}
   aa = []
   for i in range(len(hexstring)):
      aa += bin[hexstring[i]]
   return aa

def b2h(a):
    num = 0
    if a[3]==1: num += 1
    if a[2]==1: num += 2
    if a[1]==1: num += 4
    if a[0]==1: num += 8
    if num<10: return chr(ord('0') + num)
    return chr(ord('a') + (num-10))
    
def bin2hex(a):
    if len(a) % 4 !=0:
        print('bin2hex Error: len(a)=', len(a))
        return -1
    val = ''
    for i in range(len(a)//4):
        val = val + b2h(a[4*i:4*i+4])
    return val

def dec2bin(d, cnt=6):    
    res = list()
    for _ in range(cnt):
        res.append(d%2)
        d = d//2
    res.reverse()
    return res

def bin2dec(b):    
    b.reverse()
    res = 0
    e = 1
    for i in b:
        res = res + e*i
        e = e*2
    b.reverse() #otocime spat
    return res


def GenerateKeys():
    return [hex2bin("fed8d4") , hex2bin("5cea3d") , hex2bin("ebd76c") , hex2bin("c51cbc")]

def xor(a,b):
    if len(a) != len(b):
        print('Error in xor: len(a)=', len(a), ', len(b)=', len(b))
        return -1
    return [(a[i]+b[i]) % 2 for i in range(len(a))]

def sbox(S,val):         
    return dec2bin(S[bin2dec(val)], len(val))

def subs(S,val):    
    return sbox(S, val[0:6]) + sbox(S, val[6:12]) + sbox(S, val[12:18]) + sbox(S, val[18:24])
    
def perm(P,val):
    if len(val) != len(P):
        print('Error in perm: len(P)=', len(P), ', len(val)=', len(val))
        return -1
    return [val[P[i]] for i in range(len(val))]
    
def Encrypt(structure, keys, plaintext):
    S = structure[0]
    P1 = structure[1]
    P2 = structure[2] 
    # Round 1
    val = xor(plaintext, keys[0])
    val = subs(S, val)
    val = perm(P1, val)
    # Round 2
    val = xor(val, keys[1])
    val = subs(S, val)
    val = perm(P2, val)
    # Round 3
    val = xor(val, keys[2])
    val = subs(S, val)    
    val = xor(val, keys[3])
    return val

def inv(a):
    val = [-1 for i in range(len(a))]
    for i in range(len(a)):
        val[a[i]] = i
    return val
    
def Decrypt(structure, keys, ciphertext):
    Sinv = inv(structure[0])
    P1inv = inv(structure[1])
    P2inv = inv(structure[2])
    # Round 1
    val = xor(ciphertext, keys[3])
    val = subs(Sinv, val)
    print('val',val)
    val = xor(val, keys[2])
    # Round 2
    val = perm(P2inv, val)
    val = subs(Sinv, val)
    val = xor(val, keys[1])
    # Round 3
    val = perm(P1inv, val)
    val = subs(Sinv, val)
    val = xor(val, keys[0])
    return val



def do_test(debug = False):
    struct = GenerateCipher()
    keys = GenerateKeys()    
    OT = hex2bin("bd4583")
    if debug: print('OT:', OT)
    ST = Encrypt(struct, keys, OT)            
    if debug: 
        print('ST:', ST)
        print('TT:', hex2bin('88683c'))
        print('STstr:', bin2hex(ST))
        print('TTstr', '88683c')
    OT2 = Decrypt(struct, keys, ST)
    if debug: print('OT2:', OT2)
    if debug: print('Korektne desifrovane:', OT==OT2)
    return OT==OT2

# print(do_test(True))

def scalar(v1,v2):
    sum = 0
    l = list()
    # print ('v1:',v1,'\nv2:',v2)
    for i in range(len(v1)):        
        l.append(v1[i]*v2[i])
        sum += v1[i]*v2[i]                
        sum %= 2
    # print('vo:',l)
    return sum

def computeLATCell(inputIndex, outputIndex, vectors, S):
    sum = 0
    for x in vectors:
        t = (-1)**(scalar(x, vectors[inputIndex])^scalar(sbox(S, x), vectors[outputIndex]))
        print(inputIndex, outputIndex, vectors[inputIndex], vectors[outputIndex],x, sbox(S, x),t )
        print(vectors[outputIndex],'.', sbox(S, x), '=',scalar(sbox(S, x), vectors[outputIndex]))
        sum += t        
    return sum

def computeLinearAproximationTable(S, pocetBitov = 6):    
    r = range(len(S))

    vectors = [dec2bin(i, pocetBitov) for i in r]   
    # return [[computeLATCell(j, i, vectors, S) for i in r] for j in r]
    return [[computeLATCell(j, i, vectors, S) for i in r] for j in r]

s = [5, 9, 7, 14, 0, 3, 2, 1, 10, 4, 13, 8, 11, 12, 6, 15]
# s = GenerateCipher()[0] 
linearTable = computeLinearAproximationTable(s,4)
for i in linearTable:
    print(i)

