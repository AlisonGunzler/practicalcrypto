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
#     1. getting padding
#     - xor 2nd bit by 1, see if still valid
#     - cont
# - know 0E -> make 14 by add 1
#     - change 1st M by i=0-255 until get 14
#     - MM = 0E xor XX
#     - repeat with next MM
    ct = bytearray(ctx)
    n = len(ct)
    num_padding = det_padding_count(ctx, server)
    print(num_padding)
    M_byte_ind = n-num_padding-1
    pt = list()

    while (M_byte_ind >= 0) :
        
        for i in range(1,num_padding+1) :
            ct[-i] = (ct[-i]^num_padding)^(num_padding+1) #ADD 1??

        # ct = f ^ n 
        # ct ^ n ^ n+1 = f^n+1

        xorfac = 0
        for j in range(256) :
            ct[M_byte_ind] = ct[M_byte_ind] ^ j
            if(server(ct) == True) :
                xorfac = j
                break
            ct[M_byte_ind] = ct[M_byte_ind] ^ j
        
        # pt ^ j = n+1 
        # n+1 ^ j = pt 
        
        new_mbyte = ct[M_byte_ind]^ xorfac ^ (num_padding+1)
        pt.insert(0, new_mbyte)

        # print(pt)
        M_byte_ind -= 1
        num_padding += 1
        
        print(pt)
    return bytes(pt)


def det_padding_count(ctx, server) :
    #     1. getting padding
#     - xor 2nd bit by 1, see if still valid
#     - cont
    ct = bytearray(ctx)
    n = len(ct)
    print(n)

    for i in range (2, 17) :
        ct[-i] ^= 1
        if(server(ct) == True) :
            return i-1
        ct[-i] ^= 1
    return 12



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

    msg = ""
    msg = bytes(msg, encoding='utf-8')
    cookie_len =0
    out = device(msg)
    num_blocks = len(out) // 16

    for i in range(1, 256) :
        msg = "a" * i
        msg = bytes(msg, encoding='utf-8')
        out = device(msg)
        nnum_blocks = len(out) // 16
        if(nnum_blocks != num_blocks) :
            break
    
    no_padding = i
    cookie_len = 16 - no_padding

    cookie_len -= 8

    return cookie_len



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
    clen = find_cookie_length(device)
    msg = b""
    out = device(msg)
    bout = bytearray(out)
    bin = bytearray(b";cookie=")
    n = clen + len(bin)
    padding = len(bout)-n 

    #where to go from here?




    



    return b""
