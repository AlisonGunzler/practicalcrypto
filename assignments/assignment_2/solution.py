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

    base_case = b""
    out_base_case = device(base_case)
    blocks_base_case = len(out_base_case) // 16

    print(len(out_base_case))
    print(blocks_base_case)

    for i in range(256) :
        case_str = "a" * i
        case = case_str.encode()
        out_case = device(case)
        blocks_case = len(out_case) // 16
        if(blocks_case != blocks_base_case) :
            alen = i-1
            break
    
    clen = blocks_base_case*16-8-alen

    return clen-1



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
    
    # 0. Initial conditions
    clen = find_cookie_length(device)
    cookie_str = ""

    # 1. do arbitrary entry to get last_blk
    msg = b""
    out = device(msg)
    bout = bytearray(out)
    last_blk = bout[-16:] # this will be the next iv
    
    # 1.5. for k = 1-clen
    for k in range(1,clen+1) :
    # 2. msg_string = 8-k 0's, the rest will be filled with b";cookie=" + cookie(1 byte)
        msg_str = "0"*(8-k) 
        # msg = 0000000 (7) ;cookie= (8) + cookie(1b)
        print(msg_str)
        msg = msg_str.encode()
        # 3. input to device msg_string, result will be aes(msg_string) ^ last_blk0
        # msg = bytes([a ^ b for a, b in zip(msg, bytes(last_blk))])
        last_blk0 = last_blk
        #TODO how to fix msg  = 7 bytes long -> halp me
        out = device(msg)
        bout = bytearray(out)
        last_blk = bout[-16:]   
        correct = bout[:16]   # aes encoding of 0's + b";cookie=" + cookie
        # 4. from i = 0-256, check every possible byte
        for i in range(0,256) :
            # 5. msg_str = "0"*(8-k) + ";cookie=" + cookie_str + str(i)
            msg_str = "0"*(8-k) + ";cookie=" + cookie_str + str(i) # this is the guess, k= len(cookie_str), cookie_str = bytes figured out
            # 6. input to device msg_string^last_blk, result will be aes(msg_string)
            msg = msg_str.encode() 
            msg = bytes([a ^ b ^ c for a, b, c in zip(msg, bytes(last_blk), bytes(last_blk0))])
            out = device(msg)
            bout = bytearray(out)
            last_blk = bout[-16:]
            # 7. compare result from 3 with result from 6, if they match, i is the next byte of cookie
            if(bout[:16] == correct):
                print("yess")
                cookie_str = chr(i) + cookie_str
                break
            # 8. repeat until cookie is found
        #TODO clen > 8, do m_str = 16 bytes??
    print(cookie_str)

    #NOTES
    #using stateful version of cbc
        #IV at end

    return b""
