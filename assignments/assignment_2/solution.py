AES_BLOCK_SIZE = 16

"""
Solution to Assignment 2

Python version 3.9 or later.

Your final submission must contain the following functions:
    - solve_padding_oracle(ctx, server)
    - find_cookie_length(server)
    - find_cookie(server)
"""


def solve_padding_oracle(ctx, server):
    """
    Recovers the original plaintext message from a given ciphertext using a padding oracle attack.

    Parameters:
        ctx (bytes): A ciphertext produced using AES in CBC mode. The first AES_BLOCK_SIZE bytes
                     of ctx are the Initialization Vector (IV), and the remaining bytes are the ciphertext.

        server (function): A padding oracle function with the signature:
                               server(ciphertext: bytes) -> bool
                           When passed a ciphertext, the server function decrypts it (using the unknown key)
                           and returns True if the resulting plaintext has valid PKCS#7 padding,
                           or False if the padding is invalid.

    Returns:
        bytes: The recovered plaintext message with the padding removed.
    """

    # get byte array for ease
    # r = bytearray(ctx)
    # b = len(r)
    # block_sz = 16
    # blocks = b // block_sz
    # pt = list()
    # iv = r[0:block_sz]

    # for st in range(blocks -1, 0, -1) :
    #     # 16 bytes in r
    #     r1 = r[st*block_sz:st*block_sz+block_sz] #current block 
    #     r2 = r[st*block_sz - block_sz:st*block_sz] #previous block

    #     for by in range(block_sz-1,-1,-1) :
    #         byte = 0
    #         for i in range(256) :
    #             # r1k = bytearray(r1)
    #             r2k = bytearray(r2)

    #             r2k[by] = r2k[by] ^ i
    #             concat_lst = iv + r1 + r2k
                
    #             if(server(concat_lst) != 0) :
    #                 byte = i
    #                 print("here")
    #                 break
    #         pt.append(byte)
    # for c in pt:
    #      print(chr(c))

    r = bytearray(ctx)
    b = 16
    pt = list()
    for st in range(len(r)//16 -1,0, -1) :
        r1 = r[st*b:st*b+b] #current block 
        r2 = r[st*b - b:st*b] #previous block
        dec_blk = blk_dec_oracle(r1, server)
        p_blk = [0] * b
        for i in range(b):
            p_blk[i] = dec_blk[i] ^ r2[i]
        pt = p_blk + pt
    return bytes(pt)


def blk_dec_oracle(r, server) :
    print("1")

    # 1. take rk = ak ⊕ (b − j + 2) for k = j, . . . , b
    
    a = last_wd_oracle(r, server)
    j = len(a) #? HALP
    b = 16

    for k in range (j,b,1) :
        
        r[k] = a[k-j] ^ (b - j + 2)

    # 2. pick r1, . . . , rj−1 at random and take i = 0

    i = 0

    # 3. take r = r1 . . . rj−2(rj−1 ⊕ i)rj . . . rb

    rn = r[0:j-2] + [r[j-1] ^ i] + r[j:b]

    # 4. if O(r|y) = 0 then increment i and go back to the previous step

    while(server(rn) == 0) :
        i = i+1
        rn = r[0:j-2] + [r[j-1] ^ i] + r[j:b]

    # 5. output rj−1 ⊕ i ⊕ (b − j + 2)
    return r[j-1] ^ i ^ (b-j+2)

def last_wd_oracle(r, server) :
    #pick a few random words r1, . . . , rb and take i = 0
    b=16
    i=0
    print(len(r))
    print("h")
    print(r[b-1] ^ i)
    #pick r = r1 . . . rb−1(rb ⊕ i)
    newl = [r[b-1] ^ i]
    print(bytearray(newl))
    print(len(r[0:b-1]))
    rn = r[0:b-1] + bytearray(newl)
    print(rn)
    #if O(r|y) = 0 then increment i and go back to the previous step
    while(server(rn) == 0) :
        i = i+1
        rn = r[0:b-1] + bytearray(r[b-1] ^ i)
    #replace rb by rb ⊕ i
    r[b-1] = r[b-1] ^ i
    #for n = b down to 2 do
    for n in range(b,2,-1) :
        #take r = r1 . . . rb−n(rb−n+1 ⊕ 1)rb−n+2 . . . rb
        r = r[0:b-n] + bytearray(r[b-n] ^ 1) + r[b-n+1:b]
        #if O(r|y) = 0 then stop and output (rb−n+1 ⊕ n). . .(rb ⊕ n)
        if(server(r) == 0) :
            return r[b-n:b]
    #output rb ⊕ 1
    return r[b-1] ^ 1


    






def find_cookie_length(device):
    """
    Determines the length (in bytes) of a secret cookie that the device appends to a plaintext message
    before encryption.

    Parameters:
        device (function): A stateful CBC encryption oracle with the signature:
                               device(path: bytes) -> bytes
                           The device takes a bytes object "path" as input and internally constructs a message:
                               msg = path + b";cookie=" + cookie
                           It then pads and encrypts this message using AES in CBC mode.
                           Importantly, the device retains its CBC state between calls, so the encryption is stateful.

    Returns:
        int: The length of the secret cookie (in bytes).
    """
    return 0


def find_cookie(device):
    """
    Recovers the secret cookie that the device appends to the plaintext message before encryption.

    Parameters:
        device (function): A stateful CBC encryption oracle with the signature:
                               device(path: bytes) -> bytes
                           The device builds the message as:
                               msg = path + b";cookie=" + cookie
                           and then pads and encrypts msg using AES in CBC mode, while maintaining the CBC chaining
                           state across calls.

    Returns:
        bytes: The secret cookie that was appended to the plaintext.
    """
    return b""
