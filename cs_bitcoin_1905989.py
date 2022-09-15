
# pip uninstall crypto
# pip install pycryptodome

# import necessary modules

from Crypto.PublicKey import RSA
from hashlib import sha512, sha256
import random

### Task 1: Create a RSA public/private key pair with 1024 bits key length [20%]

#The following function generateRSAKeys creates the RSA public/private key pair.
def generateRSAKeys(numBits):
    keyPair = RSA.generate(numBits)
    
    return keyPair

###  generating RSA public/private keys.

numBits = 1024
keyPair = generateRSAKeys(numBits)
print("Public key:  n={", hex(keyPair.n), "}, e={", hex(keyPair.e), "})")
print('  ')
print("Private key: n={", hex(keyPair.n), "}, d={", hex(keyPair.d), "})")
print('  ')


#The following function digitalSignRSA digitally sign a message of type "bytes"
# with RSA private key of keyPair
#- input: msg and keyPairRSA
#- output: signature (type: int)

def digitalSignRSA(msg, keyPairRSA):
    ### RSA sign the message
    # msg = bytes('A message for signing', 'utf-8')

    # compute the hash value of the message to be signed with hash algorithm SHA-256
    hashValue = int.from_bytes(sha256(msg).digest(), byteorder='big')
    
    #sign (encrypt) the hash value of the message with RSA priviate key
    # only the person with RSA private key can perform the operation
    signature = pow(hashValue, keyPair.d, keyPair.n)
    
    return(hashValue, signature)



#The following function digitalVerifyRSA verify the signature of a message of type "bytes"
# with RSA public key of keyPair
#- input: msg, keyPairRSA and signature
#- output:  validity (type: boolean)
def digitalVerifyRSA(msg, keyPairRSA, signature):
    ### Verify the digital signature

    # compute the hash value of the message to be signed with hash algorithm SHA-256
    hashValue = int.from_bytes(sha256(msg).digest(), byteorder='big')
        
    # decrypt the signature of the message to obtain the hash value with RSA public key
    # everyone with RSA public key can perform the operation
    hashFromSignature = pow(signature, keyPair.e, keyPair.n)

    validity = (hashValue == hashFromSignature)
    return(validity)




#The following function checkOneNonce will check if one nonce can solve the puzzle
#This function can be used to implement the proof-of-work 
#- input: numZerosNeeded (type: int), required number of least significant bits to be zero.
#         nonce (type: int), a random number to be checked
#- output: validity (type: boolean), true or false on the validity of this nonce.
def checkOneNonce(numZerosNeeded, nonce):

    # Note that hash function sha256 accepts input of type byte.
    # so we convert random number nonce to a byte array nByte
    #convert the random integer to a byte array
    nByte = bytes(str(nonce), 'utf-8')

    # compute the hash of the nonce
    hash = int.from_bytes(sha256(nByte).digest(), byteorder='big')

    # convert the hash value to binary number and extract the needed LSBs.
    hashBin = bin(hash) 
    hashLSB = int(hashBin[-numZerosNeeded:]) 
    
    # check if the LSBs are all zero 
    if hashLSB == 0: 
        print('nRand:', nonce, '; hash_lsb:', hashLSB)
    validity = (hashLSB == 0)
    return (validity)

### Task 2: Find a nonce which produces a hash value with hash algorithm SHA-256
### satisfying requirement of the 5 least significant bits (LSB) being zero  [50%]

# generating a random number as a nonce, checking only one nonce with function checkOneNonce,

numZerosNeeded = 5
valid = False
numOfAttempts = 0
while not (valid) and (numOfAttempts <10000):
    nonce = random.randint(0, 1000000)
    valid = checkOneNonce(numZerosNeeded, nonce)
    numOfAttempts += 1

if not(valid):
    print("A valid nonce not found")
    #print(numOfAttempts)

else:
    #print("Number of attempts: ", numOfAttempts)
    print('Valid nonce : ', nonce)
    print(' ')



### Task3: Digitally sign the nonce and your student number with the RSA private key [30%]
# Hint: you should generate the message to be signed (a string with the nonce and your student number),
# then utilize Example 2 in the provided sample program to sign the message with RSA key pair generated in Task 1.

### Example 2: calling function digitalSignRSA to sign a given message

studentID = '1234567'
message = str(nonce) + ' ' + studentID
msg = bytes(message, 'utf-8')
print("Message : ", message)
(hashValue, signature) = digitalSignRSA(msg, keyPair)
print("Hash value of message:", hashValue)
print("Signature:", hex(signature))
print('  ')



### verifying a message signature using function digitalVerifyRSA

# Verify the true digital signature with the original message
studentID = '1234567'
message = str(nonce) + ' ' + studentID
msg = bytes(message, 'utf-8')
validity = digitalVerifyRSA(msg, keyPair, signature)
print("Signature validity:", validity)
print('  ')

# Verify the true digital signature with a tampered message
msgTampered = bytes('A message for signing (tampered)', 'utf-8')
validity = digitalVerifyRSA(msgTampered, keyPair, signature)
print("Signature validity:", validity)
print('  ')
