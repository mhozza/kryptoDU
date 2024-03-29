#!/usr/bin/pypy
import math
import sys
import pickle
import operator
import random

#cipher structure
def GenerateCipher():
    P1 = [22, 13, 10, 18, 3, 1, 23, 20, 15, 2, 0, 21, 11, 12, 19, 16, 8, 14, 4, 5, 17, 6, 9, 7]
    P2 = [2, 1, 6, 21, 23, 13, 18, 5, 14, 4, 9, 8, 20, 19, 7, 10, 16, 17, 22, 11, 0, 12, 3, 15]
    S = [24, 19, 43, 35, 12, 29, 40, 21, 33, 58, 48, 59, 22, 60, 32, 54, 17, 6, 56, 52, 37, 44, 10, 50, 15, 49, 30, 61, 13, 18, 46, 39, 16, 31, 28, 8, 53, 7, 51, 47, 41, 38, 26, 36, 57, 27, 0, 1, 62, 2, 63, 14, 23, 20, 3, 4, 45, 5, 11, 34, 55, 42, 9, 25]
    return [S, P1, P2]

def GenerateKeys():
    return [hex2bin('41da24'), hex2bin('5d61b9'), hex2bin('7a64aa'), hex2bin('9494a5')] 

#conversion functions
def getReversedList(l):
    c = l[:]
    c.reverse()
    return c

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


#helper functions
def xor(a,b):
    if len(a) != len(b):
        print('Error in xor: len(a)=', len(a), ', len(b)=', len(b))
        return -1
    return [(a[i]+b[i]) % 2 for i in range(len(a))]

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

def sbox(S,val):
    return dec2bin(S[bin2dec(val)], len(val))

def subs(S,val):
    return sbox(S, val[0:6]) + sbox(S, val[6:12]) + sbox(S, val[12:18]) + sbox(S, val[18:24])

def perm(P,val):
    if len(val) != len(P):
        print('Error in perm: len(P)=', len(P), ', len(val)=', len(val))
        return -1
    return [val[P[i]] for i in range(len(val))]

def inv(a):
    val = [-1 for i in range(len(a))]
    for i in range(len(a)):
        val[a[i]] = i
    return val
    
def scalar(v1,v2):
    sum = 0
    for i in range(len(v1)):
        sum += v1[i]*v2[i]
        sum %= 2
    return sum

#encryption and decryption
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

def Decrypt(structure, keys, ciphertext):
    Sinv = inv(structure[0])
    P1inv = inv(structure[1])
    P2inv = inv(structure[2])
    # Round 1
    val = xor(ciphertext, keys[3])
    val = subs(Sinv, val)
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

def partialDecrypt(structure, key, ciphertext, permutation=False, levels = 4):
    Sinv = inv(structure[0])
    if levels==4:
        Pinv = inv(structure[2])
    else:
        Pinv = inv(structure[1])
    val = xor(ciphertext, key)
    val = subs(Sinv, val)
    if permutation:
        val = perm(Pinv, val)
    return val

def generateDecryptedData(keys, fname_in = 'h2-data.txt', fname_out = "data2.txt", levels=4):
    data = loadData(fname_in)
    f = open(fname_out,'w')
    print('Decrypting...')
    for d in data:
        f.write('%(d1)s %(d2)s\n' % {'d1':bin2hex(d[0]), 'd2':bin2hex(partialDecrypt(s,keys,d[1],permutation=True, levels=levels))})

#LAT
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

def getLinearAproximationTable():
    f = open('lineartable.dat','rb')
    linearTable = pickle.load(f)
    # computeLinearAproximationTable(s[0],6)
    f.close()
    # f = open('lineartable.dat','wb')
    # pickle.dump(linearTable,f,2)
    # f.close()
    f = open('biasTable.dat','rb')
    biasTable = pickle.load(f)
    # = [[i/(2*linearTable[0][0]) for i in j] for j in linearTable]
    f.close()
    # f = open('biasTable.dat','wb')
    # pickle.dump(biasTable,f,2)
    # f.close()
    return (linearTable, biasTable)


class CipherVisualizer:
    def __init__(self, structure, linearTable, biasTable, sboxes=None, levels = 4, bits = 24):
        self.levels = levels
        self.sboxcnt = 4
        self.bits = bits
        self.structure = structure
        self.biasTable = biasTable
        self.linearTable = linearTable
        if not sboxes:
            self.sboxes = [[[0 for i in range(self.bits)],[0 for i in range(self.bits)]] for k in range(self.levels-1)]
        else:
            self.sboxes = sboxes        

    def _reset(self):
        self.__init__(self.structure, self.linearTable, self.biasTable, None, self.levels, self.bits)

    def _getBestOutput(self, inBits):
        inVal = bin2dec(inBits)
        row = [abs(i) for i in self.linearTable[inVal]]
        max_index = max(enumerate(row), key=operator.itemgetter(1))[0]
        return dec2bin(max_index)

    def getLinearCombinations(self):
        topSboxes = [(i,j) for i in range(len(self.linearTable)) for j in range(len(self.linearTable[i])) if abs(self.linearTable[i][j])>=12]

        sboxCombinations = [(i,j)for i in range(self.sboxcnt) for j in range(self.sboxcnt)]
        sboxTuple = [(i,j) for i in topSboxes for j in topSboxes]

        lcombs = list()
        for c,i in enumerate(sboxTuple):
            for j in sboxCombinations:
                self._reset()
                self.setSBox(0, 0, j[0], dec2bin(i[0][0]))
                self.setSBox(1, 0, j[0], dec2bin(i[0][1]))
                self.setSBox(0, 0, j[1], dec2bin(i[1][0]))
                self.setSBox(1, 0, j[1], dec2bin(i[1][1]))
                if self.levels>3:
                    for ind,k in enumerate(self.getActiveSboxes(1)):
                        if k:
                            self.setSBox(1,1,ind,self._getBestOutput(self.sboxes[1][0][ind*6:(ind+1)*6]))
                t = self.sboxes[:]
                lc = (abs(self._computeBias()),t)
                lcombs.append(lc)
            sys.stderr.write('%(index)d of %(count)d = %(percent).3f%%\n' % {'index':c, 'count':len(sboxTuple), 'percent':(c*100.0)/len(sboxTuple)})

        lcombs.sort(reverse=True)
        lcombs2 = [i for j,i in enumerate(lcombs) if j==0 or cmp(i, lcombs[j-1])!=0]
        return lcombs2

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
        if level<=1 and self.levels>3:
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

    def _list2String(self, lst):
        s = ''
        for i in lst:
            s+=str(i)+' '
        return s

    def _printBits(self, i, j, bits, colors=True):
        color = ('\033[0;37m', '\033[1;31m')
        ls = self._list2String([color[b]+repr(b).rjust(2)+color[0] for b in bits])
        print(str(i)+'.'+str(j)+':'+ls)

    def _computeBias(self):
        globalBias = 2**(self.levels-3)
        for i,l in enumerate(self.sboxes):
            if i<self.levels-1:
                sboxBias = 2**(self.sboxcnt-1)
                for j in range(4):
                    vstup = bin2dec(self.sboxes[i][0][j*6:(1+j)*6])
                    vystup = bin2dec(self.sboxes[i][1][j*6:(1+j)*6])
                    sboxBias *=self.biasTable[vstup][vystup]
            if i<self.levels-2:
                globalBias*=sboxBias
        return globalBias

    def getLinearEquation(self):
        vstup = [i for i,j in enumerate(self.sboxes[0][0]) if j]
        vystup = [i for i,j in enumerate(self.sboxes[self.levels-2][0]) if j]
        return (vstup, vystup)

    def _isZero(self, bits):
        for i in bits:
            if i==1:
                return False
        return True

    def getActiveSboxes(self, level = 2):
        s = list()
        for i in range(self.sboxcnt):
            if self._isZero(self.sboxes[level][0][i*6:(i+1)*6]):
                s.append(0)
            else:
                s.append(1)
        return s

    def visualize(self):
        ls = self._list2String([repr(i).rjust(2) for i in range(self.bits)])
        print('l  :' + ls)
        globalBias = 2**(self.levels-3)
        for i,l in enumerate(self.sboxes):
            self._printBits(i,0,l[0][:])
            if i<self.levels-1:
                print('    '+' _       _     _  '*4)
                s = ""
                sboxBias = 2**(self.sboxcnt-1)
                for j in range(4):
                    vstup = bin2dec(self.sboxes[i][0][j*6:(1+j)*6])
                    vystup = bin2dec(self.sboxes[i][1][j*6:(1+j)*6])
                    sboxBias *=self.biasTable[vstup][vystup]
                    s+='|_ S-box:_{0:.3f}_| '.format(self.biasTable[vstup][vystup])
                s+='  Bias: %(bias) .4f' % {'bias':sboxBias}
                print('    ' + s)
                self._printBits(i,1,l[1][:])
            if i<self.levels-2:
                print('     _______________________________      ________________________________  ')
                print('    |_______________________________ Perm ________________________________| ')
                globalBias*=sboxBias

        print('l  :'+ ls)
        print('Bias: %(bias) .5f' % {'bias':globalBias})

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
        pickle.dump(self.sboxes,f,2)
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
                if value != None and 0 <= int(value) < self.levels-1:
                    level = int(value)
                print('Current level:', level)

            if command=='s' or command=='sbox':
                if value != None and 0 <= int(value) < self.sboxcnt:
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
                self._reset()
                self.visualize()

            if command=='save':
                self.save(value)

            if command=='load':
                self.load(value)



def loadData(fname='h2-data.txt'):
    f = open(fname)
    data = list()
    for line in f:
        (oth,cth) = line.split()
        (ot, ct) = (hex2bin(oth),hex2bin(cth))
        data.append((ot,ct))
    f.close()
    return data


#key generation
def generateOneKey(index, lst, *params):
    c = sum(lst[0:index+1])-1
    if lst[index]:
        return dec2bin(params[c])
    return [0]*6

def generateAllKeys(activeSboxes):
    cnt = sum(activeSboxes)
    if cnt==4:
        keys = [generateOneKey(0,activeSboxes,i,j,k,l) + generateOneKey(1,activeSboxes,i,j,k,l) + generateOneKey(2,activeSboxes,i,j,k,l) + generateOneKey(3,activeSboxes,i,j,k,l) for i in range(2**6) for j in range(2**6) for k in range(2**6) for l in range(2**6)]
    if cnt==3:
        keys = [generateOneKey(0,activeSboxes,i,j,k) + generateOneKey(1,activeSboxes,i,j,k) + generateOneKey(2,activeSboxes,i,j,k) + generateOneKey(3,activeSboxes,i,j,k) for i in range(2**6) for j in range(2**6) for k in range(2**6)]
    if cnt==2:
        keys = [generateOneKey(0,activeSboxes,i,j) + generateOneKey(1,activeSboxes,i,j) + generateOneKey(2,activeSboxes,i,j) + generateOneKey(3,activeSboxes,i,j) for i in range(2**6) for j in range(2**6)]
    if cnt==1:
        keys = [generateOneKey(0,activeSboxes,i) + generateOneKey(1,activeSboxes,i) + generateOneKey(2,activeSboxes,i) + generateOneKey(3,activeSboxes,i) for i in range(2**6)]
    return keys


def linearKryptoAnalysys(s, cv, interactive = True, decrypt = True, fname = "h2-data.txt"):
    linearTable, biasTable = getLinearAproximationTable()
    if interactive:
        cv.visualize()
        cv.startInteractivrMode()

    if decrypt:
        linearEquation = cv.getLinearEquation()
        sys.stderr.write('Generating keys...\n')
        activeSboxes = cv.getActiveSboxes(cv.levels-2)
        keys = generateAllKeys(activeSboxes)
        sys.stderr.write('Generated {} keys\n'.format(len(keys)))
        keyDict = [0.0 for i in range(2**(6*sum(activeSboxes)))]

        sys.stderr.write('Loading data...\n')
        data = loadData(fname)
        sys.stderr.write('Decrypting...\n')
        for i,k in enumerate(keys):
            for d in data:
                if xorbitsLE(d[0],partialDecrypt(s,k,d[1], levels=cv.levels),linearEquation):
                    keyDict[i]+=1
            keyDict[i]/=len(data)
            if  i % 20==0:
                sys.stderr.write('%(index)d of %(count)d = %(percent).3f%%\n' % {'index':i, 'count':len(keys), 'percent':(i*100.0)/len(keys)})

        sys.stderr.write('Saving keys...\n')
        sys.stderr.write('Done.\n')
        keyDictSort = [(abs(k-0.5), i) for i,k in enumerate(keyDict)]
        keyDictSort.sort(reverse=True)

        print('Top 5 keys:')
        for k,i in keyDictSort[0:5]:
            print('{0:.5f}'.format(k), keys[i], i)
        return keyDictSort

#get last key from cipher
def getLastKey(fname = 'h2-data.txt', levels = 4):
    linearTable, biasTable = getLinearAproximationTable()
    cv = CipherVisualizer(s, linearTable, biasTable, levels=levels)
    # linearKryptoAnalysys(s, cv, interactive=True, decrypt=True)

    # f = open('lincomb.dat','wb')
    # linCombs = cv.getLinearCombinations()
    # pickle.dump(linCombs,f,2)
    # f.close()
    # for i in linCombs[0:30]:
    #     print(i)

    f = open('lincomb.dat','rb')
    linCombs = pickle.load(f)
    f.close()

    usedLC = list()
    keyParts = [0,0,0,0]
    index = 1
    keys = []
    while keyParts != [1]*4:
    # for index in range(1,30):
        c = linCombs[index]    
        cv = CipherVisualizer(s, linearTable, biasTable, c[1], levels=levels)
        active = cv.getActiveSboxes(cv.levels-2)
        newkey = False
        if sum(active)<=2:
            for i,j in enumerate(active):
                if j and not keyParts[i]:
                    newkey = True            
                    keyParts[i] = 1

        if newkey:
            print('-'*40)
            print('New Key Part:')
            print('index:',index)
            print('bias:',c[0])
            print('parts:',active)
            print('Breaking...')
            keys = linearKryptoAnalysys(s, cv, interactive=False, decrypt=True, fname=fname)

        index+=1

#getting last two keys
def decryptLast(structure, ri = 0, filename='data3.txt'):
    Sinv = structure[0]
    data = loadData(filename)
    for i in range(2**6):
        for j in range(2**6):
            k0, k1 = (dec2bin(i), dec2bin(j))
            found = True
            for d in data:                
                val = xor(d[0][ri*6:(ri+1)*6], k0)
                val = subs(Sinv, val)
                val = xor(val, k1)
                if val != d[1][ri*6:(ri+1)*6]:                    
                    found = False
                    break
            if found:
                return (k0,k1)
    return None

def do_test(debug = False):
    data = loadData()
    struct = GenerateCipher()
    keys = GenerateKeys()
    for d in data:
        OT = d[0]
        if debug: print('OT:', OT)
        ST = Encrypt(struct, keys, OT)
        TT = d[1]
        if debug:
            print('ST:', ST)
            print('TT:', TT)
            print('STstr:', bin2hex(ST))
            print('TTstr', bin2hex(TT))
        OT2 = Decrypt(struct, keys, ST)
        if debug: print('OT2:', OT2)
        if debug: print('Korektne desifrovane:', OT==OT2)
        if OT!=OT2: return False
    return True

s = GenerateCipher()
# k1 = [0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0]
# k2 = perm(s[1],[1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0])
# k3 = perm(s[2],[1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1])
# k4 = [1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1]
# print(bin2hex(k1), bin2hex(k2), bin2hex(k3), bin2hex(k4))
# keys: ('41da24', '5d61b9', '7a64aa', '9494a5')

# getLastKey("h2-data.txt", 4)
# generateDecryptedData(k4, 'h2-data.txt', "data2.txt", levels = 4)
# getLastKey("data2.txt", 3)
# generateDecryptedData(k3, 'data2.txt', "data3.txt", levels = 3)

# keys = list()
# for i in range(4):
#     keys.append(decryptLast(s,i, "data3.txt"))    
# if keys != [None]*4:    
#     print keys

# print(do_test(True))



linearTable, biasTable = getLinearAproximationTable()
cv = CipherVisualizer(s, linearTable, biasTable, levels=4)
linCombs = cv.getLinearCombinations()
cv.sboxes = linCombs[1][1]
linearKryptoAnalysys(s, cv, interactive = True, decrypt = False)