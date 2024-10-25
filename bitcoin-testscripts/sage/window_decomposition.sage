# This script is used to verify the logic of decomposing an integer
# into a window width representation and then reconstructing the integer
# from the window width representation.

import random

N_BITS: Integer = 254 # Number of bits in the integer
LIMB_SIZE: Integer = 30 # Number of bits in a limb
WINDOW_SIZE: Integer = 3 # Window size

def to_limbs(a: Integer, limb_size: Integer) -> list[Integer]:
    """
    Converts the given integer a into a list of 254-bit limbs
    """

    limbs = []
    while a >= 1:
        c = a % (1 << limb_size)
        limbs.append(c)
        a = a - c
        a = a // (1 << limb_size)
    
    return limbs

def chunks(lst, n):
    """
    Yield successive n-sized chunks from lst
    """

    for i in range(0, len(lst), n):
        yield lst[i:i+n]

def recover_to_limbs(window_decomposition: list[Integer], width: Integer, limb_size: Integer) -> list[Integer]:
    """
    Recovers the integer in the limb format from the window decomposition
    """

    assert limb_size % width == 0, "limb size must be a multiple of the window width"
    chunk_size = limb_size // width

    return [sum([x*(1<<(i*width)) for i, x in enumerate(chunk)]) for chunk in chunks(window_decomposition, chunk_size)]

# Pick a random integer
a = Integer(random.randint(0, 1<<N_BITS))
print(f"Random integer: {a}")

# Show the limbs
limbs = to_limbs(a, LIMB_SIZE)
print(f"Limbs: {limbs}")

# Show the window decomposition
window_decomposition = to_limbs(a, WINDOW_SIZE)
print(f"Window decomposition: {window_decomposition}")

# Show the recovered limbs
print(f"Recover: {recover_to_limbs(window_decomposition, WINDOW_SIZE, LIMB_SIZE)}")


