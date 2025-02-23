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
    M_byte_ind = n-num_padding-1
    pt = list()

    while (n != num_padding) :
        for i in range(num_padding) :
            print("ok")
            print(len(ct))
            print(i)
            print(n-i-1)
            print(num_padding)
            ct[n-i-1] = ct[n-i-1] ^ 1 #ADD 1??
        xorfac = 0
        for j in range(256) :
            ct1 = bytearray(ct)
            ct1[M_byte_ind] = ct1[M_byte_ind] ^ j
            if(server(ct1) == 1) :
                xorfac = j
        ct[M_byte_ind] = ct[M_byte_ind] ^ xorfac
        new_mbyte = xorfac ^ (num_padding ^ 1) #ADD 1??
        pt.insert(0, new_mbyte)
        print(pt)
        n = n+1
    return bytes(pt)


def det_padding_count(ctx, server) :
    ct = bytearray(ctx)
    n = len(ct)
    for i in range (0, 16) :
        ct[n-1-i] = ct[n-1-i] ^ 1
        if(server(ct) == 1) :
            print(i)
            return i
        ct = bytearray(ctx)
    return 0



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
