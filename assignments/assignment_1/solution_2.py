# Python version 3.9 or later

# Complete the functions below and include this file in your submission.
#
# You can verify your solution by running `problem_2.py`. See `problem_2.py` for more
# details.

# ------------------------------------- IMPORTANT --------------------------------------
# Do NOT modify the name or signature of the three functions below. You can, however,
# add any additional functons to this file.
# --------------------------------------------------------------------------------------

# Given a ciphertext enciphered using the Caesar cipher, recover the plaintext.
# In the Caesar cipher, each byte of the plaintext is XORed by the key (which is a
# single byte) to compute the ciphertext.
#
# The input `ciphertext` is a bytestring i.e., it is an instance of `bytes`
# (see https://docs.python.org/3.9/library/stdtypes.html#binary-sequence-types-bytes-bytearray-memoryview).
# The function should return the plaintext, which is also a bytestring.
def break_caesar_cipher(ciphertext):

    #initial conditions for loop to find the best match
    best_key = 2147483647
    best_plaintext = ciphertext

    # frequencies obtained from https://en.wikipedia.org/wiki/Letter_frequency
    frequenciesa_z = [0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609, 0.0697, 0.0015, 0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193, 0.0001, 0.0599, 0.0633, 0.0906, 0.0276, 0.0098, 0.0236, 0.0015, 0.0197, 0.0007] 
    # value of lowercase a in ascii
    a = 97

    for key in range(256): #256 possible keys in a byte

        # initialize plaintext as the ciphertext
        plaintext = bytearray(ciphertext) 

        # xor each byte in the plaintext with the assumed key 
        for index in range(len(plaintext)):
            plaintext[index] ^= key
        
        # initialize loop variables and constants
        n = len(ciphertext)
        xkey = 0.0

        # only have frequency of lowercase letters 
        lower_plaintext = plaintext.lower()
        
        #calculate the total xkey using the given formula
        for ascii in range(26):  
            letter = chr(a+ascii) #gets each lowercase character
            #calculates xkey and adds to running total
            na = str(lower_plaintext).count(letter) 
            pa = frequenciesa_z[ascii]
            xkey += ((na - (pa * n)) ** 2) / (pa * n)
                
        #a smaller xkey means a better guess at the decoded message
        if xkey < best_key:
            best_key = xkey
            best_plaintext = plaintext 

    return bytes(best_plaintext)

# Given a ciphertext enciphered using a Vigenere cipher, find the length of the secret
# key using the 'index of coincidence' method.
#
# The input `ciphertext` is a bytestring.
# The function returns the key length, which is an `int`.
def find_vigenere_key_length(ciphertext):

    #possible key lengths 
    num_possible_lengths = 20

    #key length cannot be 0
    averages = [0] * (num_possible_lengths-1)
    
    #for each possible key length
    for length in range(1, num_possible_lengths) :

        # initialize index of coincidence
        ic = 0

        #seperate into columns and total all indexed
        for column in range(length) :
            text = everyotherbyte(ciphertext, column, length)
            N = len(text)
            # denominator of index of coincidence function
            denom = N * (N-1)
            # edge case to prevent error. If the size is less than 20 its unlikely to be solvable.
            if(denom == 0) :
                return 1
            # for every possible character
            for letter in range(256) :
                ni = str(text).count(chr(letter))
                # numerator of index of coincidence function
                num = ni * (ni-1)
                ic += num/denom
        # average across all columns
        averages[length-1] = ic / length
    
    return averages.index(max(averages)) + 1

# return every nth byte given a start point 
def everyotherbyte(ciphertext, start, jump) :
    everyother = bytearray()
    ciphertext = bytearray(ciphertext)
    for i in range(start, len(ciphertext), jump):
        everyother.append(ciphertext[i])
    return bytes(everyother)

# Given a ciphertext enciphered using a Vigenere cipher and the length of the key, 
# recover the plaintext.
#
# The input `ciphertext` is a bytestring.
# The function should return the plaintext, which is also a bytestring.
def break_vigenere_cipher(ciphertext, key_length):
    parts = list()
    plaintext = bytearray()
    # for each caesar cipher in the vigenere
    for index in range(key_length):
        # get every nth byte, this is now a normal caesar cipher
        everyother = everyotherbyte(ciphertext, index, key_length)
        deciphered_everyother = break_caesar_cipher(everyother)
        # append newly deciphered part of the ciphertext
        parts.append(deciphered_everyother)
    # combine the stored parts in an interlocking pattern
    for letter in range(len(ciphertext)) :
        plaintext.append(parts[letter % key_length][int(letter / key_length)])
    return bytes(plaintext)
