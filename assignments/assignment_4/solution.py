from tinyec.registry import get_curve
import hashlib
"""
Solution to Assignment 4

Python version 3.9 or later.

Your final submission must contain the following functions:
    - compute_ecdsa_sk(params)
    - modify_user_storage(params)

You might require the following packages to implement your solution:
    - pycryptodome: Install by running `pip install pycryptodome`.
    - tinyec: Install by running `pip install tinyec`.
    - dissononce: Install by running `pip install dissononce`.
See 'problem.py' for usage examples.
"""


def compute_ecdsa_sk(params):
    """
    Recovers the server's ECDSA secret key.

    Parameters:
        params (AttackParams): An instance of AttackParams (defined in 'problem.py').

    Returns:
        int: The recovered ECDSA secret key.
    """
    # class AttackParams:
    # def __init__(self, client_keypair, server):
    #     self.client_static_pk = client_keypair.public
    #     self.server_static_pk = server.get_static_pk()
    #     self.get_client_handshake_message = lambda: client(
    #         client_keypair, self.server_static_pk
    #     )
    #     self.check_update = server.check_update
    #     self.update_storage = server.update_storage

    # initial variables
    client_static_pk = params.client_static_pk
    server_static_pk = params.server_static_pk
    get_client_handshake_message = params.get_client_handshake_message
    check_update = params.check_update
    update_storage = params.update_storage

    hm = get_client_handshake_message()
    status_msg0, sig = check_update()
    # sig = (r, s)
    r0 = sig[0]
    s0 = sig[1]

    curve = get_curve("secp256r1")
    N = curve.field.n
    
    done = False
    while not done:
        status_msg, sig = check_update()
        r = sig[0]
        s = sig[1]
        if(r == r0):
            done = True

    print(r)
    print(r0)
    print(status_msg)
    print(status_msg0)
    e0 = int.from_bytes(hashlib.sha256(status_msg0).digest(), "big") % N
    e = int.from_bytes(hashlib.sha256(status_msg).digest(), "big") % N

    sk = (((s0 * (e0-e))% N * pow(r*(s0-s), -1, N)) - (e0 * pow(r, -1, N) % N) ) % N
    print(sk)

    
    return sk


def modify_user_storage(params, target_data):
    """
    Modify the registered user's storage.

    Parameters:
        params (AttackParams): An instance of AttackParams (defined in 'problem.py').

        target_data (bytes): The user's storage should be set to this byte string at the end of the
            attack.

    Returns: No return value.
    """
    sk = compute_ecdsa_sk(params)
    pass
