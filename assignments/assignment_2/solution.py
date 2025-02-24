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
    # 1: take last 2 blocks
    ct = bytearray(ctx)
    block_size = 16
    num_blocks = len(ct) // 16
    pt = []

    while(num_blocks > 1) :
        
        #last block
        cn_index = (num_blocks-1) * block_size
        cn_index2 = num_blocks * block_size
        cn = ct[cn_index:cn_index2]

        #second to last block
        iv_index = (num_blocks-2) * block_size
        iv_index2 = (num_blocks-1) * block_size
        ivo = ct[iv_index:iv_index2]

        pt_block = [0]*16

        # set iv to 0
        iv = bytearray([0]*16)
        # store decrypted ciphertext
        cd = bytearray([0] * 16)
        
        #for each byte in the block
        for i in range(1,17) :
            # padding should be i 

            # find iv value to get padding=i
            correct_iv = 0

            #for each possible byte
            for j in range(0,256) :
                #add j to iv
                iv[-i] = j
                concat_blocks = iv + cn
                if(server(concat_blocks)) :
                    correct_iv = j
                    break
            cd[-i] = i ^ correct_iv
            pt_block[-i] = cd[-i] ^ ivo[-i]

            #TODO logic to turn 1 to 2
            for k in range(1,i+1) :
                iv[-k] = cd[-k] ^ (i+1)


        num_blocks -= 1
        pt = pt_block + pt
        
    # characters = [chr(n) for n in pt]   
    # print(characters)

    #padding is last digit of plaintext
    padding_ct = pt[-1]

    #remove padding and return as bytes
    return bytes(bytearray(pt[:-padding_ct]))




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
