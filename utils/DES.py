import re

plainIP = [58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17,  9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7]

keyP1 = [57, 49, 41, 33, 25, 17,  9,
		1, 58, 50, 42, 34, 26, 18,
		10,  2, 59, 51, 43, 35, 27,
		19, 11,  3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14,  6, 61, 53, 45, 37, 29,
		21, 13,  5, 28, 20, 12,  4]

keyP2 = [14, 17, 11, 24,  1,  5,  3, 28,
		15,  6, 21, 10, 23, 19, 12,  4,
		26,  8, 16,  7, 27, 20, 13,  2,
		41, 52, 31, 37, 47, 55, 30, 40,
		51, 45, 33, 48, 44, 49, 39, 56,
		34, 53, 46, 42, 50, 36, 29, 32]

shift = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

plainExpands = [32,  1,  2,  3,  4,  5,
			4,  5,  6,  7,  8,  9,
			8,  9, 10, 11, 12, 13,
			12, 13, 14, 15, 16, 17,
			16, 17, 18, 19, 20, 21,
			20, 21, 22, 23, 24, 25,
			24, 25, 26, 27, 28, 29,
			28, 29, 30, 31, 32,  1]

sBox = [
	[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
	[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
	[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
	[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
	],

	[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
	[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
	[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
	[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
	],

	[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
	[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
	[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
	[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
	],

	[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
	[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
	[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
	[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
	],

	[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
	[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
	[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
	[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
	],

	[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
	[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
	[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
	[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
	],

	[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
	[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
	[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
	[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
	],

	[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
	[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
	[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
	[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
	]]

plainP2 = [16,  7, 20, 21, 29, 12, 28, 17,
		1, 15, 23, 26,  5, 18, 31, 10,
		2,  8, 24, 14, 32, 27,  3,  9,
		19, 13, 30,  6, 22, 11,  4, 25]

finalPermut = [40, 8, 48, 16, 56, 24, 64, 32,
			39, 7, 47, 15, 55, 23, 63, 31,
			38, 6, 46, 14, 54, 22, 62, 30,
			37, 5, 45, 13, 53, 21, 61, 29,
			36, 4, 44, 12, 52, 20, 60, 28,
			35, 3, 43, 11, 51, 19, 59, 27,
			34, 2, 42, 10, 50, 18, 58, 26,
			33, 1, 41,  9, 49, 17, 57, 25]

def toAscii(pure):
	asciiPure = []
	y=0
	if len(pure)<8:
		y=len(pure)
		for x in range(y):
			asciiPure.insert(x, int(ord(pure[x])))
			asciiPure[x]='{0:08b}'.format(asciiPure[x])
			for x in range(y,8):
				asciiPure.insert(x, '00000000')
	else:
			for x in range(8):
				asciiPure.insert(x, int(ord(pure[x])))
				asciiPure[x]='{0:08b}'.format(asciiPure[x])
	return asciiPure

def toBinary(pure):
	binaryPure = []
	for x in range(len(pure)):
		for y in range(len(pure)):
			binaryPure.append(pure[x][y])
		return binaryPure

def toPermut(pure, permutation):
	permutedPure = []
	for x in range(len(permutation)):
		permutedPure.append(pure[permutation[x]-1])
	return permutedPure

def toLeftRight(pure):
	left = []
	right = []
	for x in range(int(len(pure)/2)):
		left.append(pure[x])
	for x in range(int(len(pure)/2),len(pure)):
		right.append(pure[x])
	return {'left':left, 'right':right}

def toShift(pure, k):
	shifted = []
	k = int(k)
	a = 0
	for x in range(len(pure)):
		if x>=len(pure)-k:
			shifted.append(pure[a])
			a = a+1
		else:
			shifted.append(pure[x+k])
	return shifted

def toCombine(left, right):
	combined = []
	for x in range(len(left)):
		combined.append(left[x])
	for x in range(len(right)):
		combined.append(right[x])

def toXor(plain, key):
	xor = []
	n = len(plain)
	for x in range(n):
		if plain[x]==key[x]:
			xor.append('0')
		else:
			xor.append('1')
	return xor

def toSbox(pure):
	box = toSplit(pure, 6)
	row = []
	col	= []

	for	x in range(len(box)):
		tempRow = []
		tempCol = []
		for y in range(6):
			if y==0 or y==5:
				tempRow.append(box[x][y])
			else:
				tempCol.append(box[x][y])
		tempRow = ''.join(tempRow)
		tempCol = ''.join(tempCol)
		tempRow = int(tempRow,2)
		tempCol = int(tempCol,2)
		row.append(tempRow)
		col.append(tempCol)

	result = []

	for x in range(8):
		temp = sBox[x][row[x]][col[x]]
		temp = '{0:04b}'.format(temp)
		result.append(temp)

	result = toBinary(result)
	return result

def toSplit(pure,bit):
	boxes = []
	for x in range(int(len(pure)/bit)):
		temp = []
		for y in range(bit):
			temp.append(pure[x*bit+y])
		boxes.append(temp)
	return boxes

K = []

def program(idx):
	keyPart['left'] = toShift(keyPart['left'], shift[idx])
	keyPart['right'] = toShift(keyPart['right'], shift[idx])
	keyCombined = toCombine(keyPart['left'], keyPart['right'])
	permutedKey2 = toPermut(keyCombined, keyP2)
	K.append(permutedKey2)
	return permutedKey2

def afterProgram(permutedKey2,plainPart):
	new = program2(permutedKey2, plainPart)
	return new

def program2(permutedKey2, plainPart):
	originRight = plainPart['right']
	plainPartExp = toPermut(plainPart['right'], plainExpands)
	xorResult = toXor(plainPartExp, permutedKey2)
	sboxResult = toSbox(xorResult)
	permutedPlain = toPermut(sboxResult, plainP2)
	xorResult2 = toXor(permutedPlain, plainPart['left'])
	return {'left':originRight, 'right':xorResult2}

def toEncrypt(plain, keyClient):
	temp2=[]
	temp=re.findall('........',plain)
	nums=int(len(plain)/8)
	if len(plain)%8:
		nums+=1
		a=len(plain)%8
		temp.append(plain[-a:])
	for x in range(nums):
		temp2.append(toEncrypt2(temp[x], keyClient))
	temp2=''.join(temp2)
	return temp2

def toDecrypt(plain, keyClient):
	global keyPart
	keyPart=[]
	global K
	K=[]
	temp2=[]
	temp=re.findall('................',plain)
	nums=int(len(plain)/16)
	if len(plain)%16:
		nums+=1
		a=len(plain)%16
		temp.append(plain[:a])
	for x in range(nums):
		temp2.append(toDecrypt2(temp[x], keyClient))
	temp2=''.join(temp2)
	return temp2

def toEncrypt2(plain, key):
    asciiPlain = toAscii(plain)
    binaryPlain = toBinary(asciiPlain)

    # key = "papamama"
    asciiKey = toAscii(key)
    binaryKey = toBinary(asciiKey)

    permutedPlain = toPermut(binaryPlain, plainIP)
    plainFirstPart = toLeftRight(permutedPlain)

    permutedKey = toPermut(binaryKey, keyP1)
    global keyPart
    keyPart = toLeftRight(permutedKey)

    for x in range(16):
        permut = program(x)
        plainFirstPart = afterProgram(permut, plainFirstPart)

    finalComb = toCombine(plainFirstPart['right'], plainFirstPart['left'])
    cipherText = toPermut(finalComb, finalPermut)
    finalText = toSplit(cipherText, 8)

    for x in range(len(finalText)):
        finalText[x] = ''.join(finalText[x])
        finalText[x] = hex(int(finalText[x], 2))[2:]

        if len(finalText[x]) == 1:
            finalText[x] = '0' + finalText[x]

    finalText = ''.join(finalText)
    return finalText


def toDecrypt2(newDecrypt, key):
    newDecrypt = re.findall('..', newDecrypt)
    for x in range(len(newDecrypt)):
        newDecrypt[x] = chr(int(newDecrypt[x], 16))

    binaryNewDecrypt = toBinary(toAscii(newDecrypt))
    permutedNewDecrypt = toPermut(binaryNewDecrypt, plainIP)
    newDecryptPart = toLeftRight(permutedNewDecrypt)

    # key = "papamama"
    asciiKey = toAscii(key)
    binaryKey = toBinary(asciiKey)
    permutedKey = toPermut(binaryKey, keyP1)

    global keyPart
    keyPart = toLeftRight(permutedKey)

    for x in range(16):
        permut = program(x)
        newDecryptPart = program2(K[x], newDecryptPart)

    finalComb = toCombine(newDecryptPart['right'], newDecryptPart['left'])
    cipherText = toPermut(finalComb, finalPermut)
    finalText = toSplit(cipherText, 8)

    for x in range(len(finalText)):
        finalText[x] = ''.join(finalText[x])
        finalText[x] = chr(int(finalText[x], 2))

    finalResult2 = ''.join(finalText)
    return finalResult2
