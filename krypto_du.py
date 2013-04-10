import math
import sys
import pickle
def getReversedList(l):
    c = l[:]
    c.reverse()
    return c

def GenerateCipher():
    P1 = [22, 13, 10, 18, 3, 1, 23, 20, 15, 2, 0, 21, 11, 12, 19, 16, 8, 14, 4, 5, 17, 6, 9, 7]
    P2 = [2, 1, 6, 21, 23, 13, 18, 5, 14, 4, 9, 8, 20, 19, 7, 10, 16, 17, 22, 11, 0, 12, 3, 15]
    S = [24, 19, 43, 35, 12, 29, 40, 21, 33, 58, 48, 59, 22, 60, 32, 54, 17, 6, 56, 52, 37, 44, 10, 50, 15, 49, 30, 61, 13, 18, 46, 39, 16, 31, 28, 8, 53, 7, 51, 47, 41, 38, 26, 36, 57, 27, 0, 1, 62, 2, 63, 14, 23, 20, 3, 4, 45, 5, 11, 34, 55, 42, 9, 25]
    # S2 = [bin2dec(getReversedList(dec2bin(i,6))) for i in S]
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

    # print([(i, P[i], val[P[i]]) for i in range(len(val))])
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
    # print('val',val)
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
    for i in range(len(v1)):
        sum += v1[i]*v2[i]
        sum %= 2
    return sum

def computeLATCell(inputIndex, outputIndex, vectors, S):
    sum = 0
    for x in vectors:
        if(scalar(x, vectors[inputIndex]) == scalar(sbox(S, x), vectors[outputIndex])):
            sum += 1
    return sum-32

def computeLinearAproximationTable(S, pocetBitov = 6):
    r = range(len(S))
    vectors = [dec2bin(i, pocetBitov) for i in r]
    return [[computeLATCell(j, i, vectors, S) for i in r] for j in r]

class CipherVisualizer:
    def __init__(self, structure, bits = 24):
        self.levels = 4
        self.sboxcnt = 4        
        self.bits = bits
        self.structure = structure
        self.sboxes = [[[0 for i in range(self.bits)],[0 for i in range(self.bits)]] for k in range(self.levels-1)]

    def subs(self, level, out):
        return self.sboxes[level][out]

    def encryptFromLevel(self, level):        
        P1 = self.structure[1]
        P2 = self.structure[2]

        if level==0:
            # Round 1
            val = self.subs(0,1)
            val = perm(P1, val)
            self.sboxes[1][0] = val[:]
        if level<=1:
            # Round 2
            val = self.subs(1,1)
            val = perm(P2, val)
            self.sboxes[2][0] = val[:]        

    def decryptFromLevel(self, level):        
        P1inv = inv(self.structure[1])
        P2inv = inv(self.structure[2])

        val = self.sboxes[level][0][:]

        if level==2:
            # Round 2
            val = perm(P2inv, val)
            self.sboxes[1][1] = val[:]
            val = self.subs(1,0)
        if level>=1:
            # Round 3
            val = perm(P1inv, val)
            self.sboxes[0][1] = val[:]

    def updateLevel(self, level):
        self.encryptFromLevel(level)
        self.decryptFromLevel(level)

    def setSBox(self, out, level, sbox, bits):
        if type(bits) is not list or len(bits)!=6:
            return         
        bits = [int(b) for b in bits]
        
        self.sboxes[level][out][sbox*6:(sbox+1)*6] = bits[:]

        self.updateLevel(level)
    
    def _printBits(self, i, j, bits, colors=True):
        color = ('\033[0;37m', '\033[1;31m')
        print(str(i)+'.'+str(j)+':',*[color[b]+repr(b).rjust(2)+color[0] for b in bits])

    def visualize(self):
        print('l  :', *[repr(i).rjust(2) for i in range(self.bits)])
        # for i,l in enumerate(self.bitTable):
        for i,l in enumerate(self.sboxes):            
            self._printBits(i,0,l[0][:])
            if i<self.levels-1:
                print('    ',' _       _     _  '*4)                
                s = ""
                for j in range(4):
                    vstup = bin2dec(self.sboxes[i][0][j*6:(1+j)*6])
                    vystup = bin2dec(self.sboxes[i][1][j*6:(1+j)*6])
                    s+='|_ S-box:_{0:.3f}_| '.format(biasTable[vstup][vystup])
                print('    ',s)
                self._printBits(i,1,l[1][:])
            if i<self.levels-2:                
                print('    ',' _______________________________      ________________________________  ')
                print('    ','|_______________________________ Perm ________________________________| ')
        print('l  :', *[repr(i).rjust(2) for i in range(self.bits)])

    def getLinearEquation(self):
        vstup = [i for i,j in enumerate(self.sboxes[0][0]) if j]
        vystup = [i for i,j in enumerate(self.sboxes[self.levels-2][0]) if j]
        return (vstup, vystup)

    def load(self, value = None):
        if type(value) is not str:
            value = 'sbox.dat'
        f = open(value,'rb')
        self.sboxes = pickle.load(f)
        f.close()
        
    def save(self, value):
        if type(value) is not str:
            value = 'sbox.dat'
        f = open(value,'wb')
        pickle.dump(self.sboxes,f)
        f.close()

    def startInteractivrMode(self):
        level = 0
        sbox = 0

        while True:
            line = sys.stdin.readline().split()
            command, value = ('exit', None)
            if len(line)>0:
                command = line[0]
            if len(line)==2:
                value = line[1]
            if len(line)>=3:
                value = line[1:]

            if not command or command == 'exit':
                print('Exitting interactive mode')
                break

            if command=='l' or command=='level':
                if value != None and 0 <= int(value) < self.levels:
                    level = int(value)
                print('Current level:', level)

            if command=='s' or command=='sbox':
                if value != None and 0 <= int(value) < 4:
                    sbox = int(value)
                print('Current s-box:', sbox)            

            if command=='i' or command=='in':
                self.setSBox(0,level, sbox, value)
                self.visualize()

            if command=='o' or command=='out':
                self.setSBox(1,level, sbox, value)
                self.visualize()

            if command=='v' or command=='view':
                self.visualize()

            if command=='r' or command=='reset':
                self.__init__(self.structure, self.bits)
                self.visualize()

            if command=='save':
                self.save(value)

            if command=='load':
                self.load(value)

def loadData():
    f = open('h2-data.txt')
    data = list()
    for line in f:
        (oth,cth) = line.split()
        (ot, ct) = (hex2bin(oth),hex2bin(cth))
        data.append((ot,ct))
    return data

def xorbits(ot,ct):
    xor = 0
    for i in ot:
        xor^=i
    for i in ct:
        xor^=i
    return xor

def xorbitsLE(ot,ct,le):
    xor = 0
    for i in le[0]:
        xor^=ot[i]
    for i in le[1]:
        xor^=ct[i]
    return xor

def partialDecrypt(structure, key, ciphertext):
    Sinv = inv(structure[0])
    # P1inv = inv(structure[1])
    # P2inv = inv(structure[2])
    # Round 1
    val = xor(ciphertext, key)
    val = subs(Sinv, val)
    return val

# s = [5, 9, 7, 14, 0, 3, 2, 1, 10, 4, 13, 8, 11, 12, 6, 15]
# s = [10, 5, 0, 13, 14, 11, 4, 6, 9, 2, 12, 3, 7, 1, 8, 15]
s = GenerateCipher()
f = open('lineartable.dat','rb')
linearTable = pickle.load(f)
# computeLinearAproximationTable(s[0],6)
f.close()
f = open('biasTable.dat','rb')
biasTable = pickle.load(f)
# = [[i/(2*linearTable[0][0]) for i in j] for j in linearTable]
f.close()

for i in range(len(linearTable)):
    for j in range(len(linearTable[i])):
        if abs(linearTable[i][j])>=12:
            print(i,j,dec2bin(i), dec2bin(j), linearTable[i][j], biasTable[i][j])

cv = CipherVisualizer(s)
cv.load()
cv.visualize()
cv.startInteractivrMode()

linearEquation = cv.getLinearEquation()

#toto zatial manualne
keys = [dec2bin(i) + [0]*12 + dec2bin(j) for i in range(2**6) for j in range(2**6)]
keyDict = [0 for i in range(2**12)]

# data = loadData()
# for i,k in enumerate(keys):    
#     for d in data:
#         if xorbitsLE(d[0],partialDecrypt(s,k,d[0]),linearEquation):
#             keyDict[i]+=1
#     keyDict[i]/=len(data)

f = open('keys.dat','rb')
# pickle.dump(keyDict,f)
keyDict = pickle.load(f)
f.close()


keyDictSort = [(abs(k-0.5), i) for i,k in enumerate(keyDict)]
keyDictSort.sort(reverse=True)

print(keyDictSort[0:20])
