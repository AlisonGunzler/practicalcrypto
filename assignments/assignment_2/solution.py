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
    cookie_str = bytearray([0]*clen)
    # 1. Use arbitrary input to get a ciphertext. The last block (last_blk) will be the next iv
    msg = b""
    out = device(msg)
    bout = bytearray(out)
    last_blk = bout[-16:] # this will be the next iv # TODO last blk??
    
    for n in range(clen % 16) :
   
        # 2. Append a set amount of zeros to get the next byte of the cookie into the first block. To get the first cookie byte, the message would be equal to  "0000000" and the device will add ";cookie=" and 1 byte of the cookie to the first block
        msg_str = "0" * (7-n)
        msg = msg_str.encode()
        # 3. I would then input the message into the device. The result will be the AES encryption of 0000000;cookie=n ^ last_blk with n being the first byte of the cookie. I will save this last_blk to a separate variable, last_blk0
        out = device(msg)
        bout = bytearray(out) # bout = 0000000;cookie=n ^ last_blk
        correct = bout[0:16]
        # print(correct)
        last_blk0 = last_blk
        last_blk = bout[-16:]

        # print(len(correct))
    
        # 4. I will then go from i= 0-256 and input msg = ("0000000" + ";cookie" + i)  ^ last_blk ^ last_blk0 to get the AES encryption of each possibility. 
        for i in range(256) :
            msg_str = "0" * (7-n) + ";cookie=" 
            msg = msg_str.encode() +  bytes(cookie_str[:n]) + bytes([i])
            # print(len(msg))
            # print(len(msg))
            # print((msg))
            blk_factor =  bytes(a ^ b for a, b in zip(last_blk, last_blk0))
            input = bytes(a ^ b for a, b in zip(blk_factor, msg))
            out = device(input)
            bout = bytearray(out)
            last_blk = bout[-16:]
            # print(bout[0:16])
        # 5. If I compare the results of step 3 and step 4, I can determine the first cookie byte.
            if(bout[0:16] == correct) :
                print("here")
                print(i)
                cookie_str[n] = i
                break

    for m in range(clen // 16) :
        for n in range(16) :
            # 2. Append a set amount of zeros to get the next byte of the cookie into the first block. To get the first cookie byte, the message would be equal to  "0000000" and the device will add ";cookie=" and 1 byte of the cookie to the first block
            msg_str = "0" * (7-n) + "0" * 16 * m
            msg = msg_str.encode()
            # 3. I would then input the message into the device. The result will be the AES encryption of 0000000;cookie=n ^ last_blk with n being the first byte of the cookie. I will save this last_blk to a separate variable, last_blk0
            out = device(msg)
            bout = bytearray(out) # bout = 0000000;cookie=n ^ last_blk
            correct = bout[0:16]
            # print(correct)
            last_blk0 = last_blk
            last_blk = bout[-16:]

            for i in range(256) :
                msg_str = "0" * (7-n) + ";cookie=" 
                msg = msg_str.encode() +  bytes(cookie_str[:n]) + bytes([i])
                # print(len(msg))
                # print(len(msg))
                # print((msg))
                blk_factor =  bytes(a ^ b for a, b in zip(last_blk, last_blk0))
                input = bytes(a ^ b for a, b in zip(blk_factor, msg))
                out = device(input)
                bout = bytearray(out)
                last_blk = bout[-16:]
                # print(bout[0:16])
            # 5. If I compare the results of step 3 and step 4, I can determine the first cookie byte.
                if(bout[0:16] == correct) :
                    print("here")
                    print(i)
                    cookie_str[n] = i
                    break





    return bytes(cookie_str)
