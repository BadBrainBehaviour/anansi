#!/usr/bin/python3

import base64
from fractions import Fraction
import secrets
import string

from numpy.polynomial import Polynomial as P


def randcoef(gfield):
    """ generate a random coefficient between 1 and gfield-1"""
    return secrets.randbelow(gfield-2)+1

def gen_coefs(threshold, gfield):
    """ generate the coefficients for the polynomial beyond the 0th degree """
    return [randcoef(gfield) for k in range(threshold-1)]

def gen_polynomial(secret, threshold, gfield):
    """ generate the polynomial object """
    coefs = [secret]
    coefs.extend(gen_coefs(threshold, gfield))
    polynomial = P(coefs)
    return polynomial

def gen_shares(polynomial, shares_num, gfield):
    """ generate the shares using the polynomial object """
    shares = []
    while len(shares)<shares_num:
        randval = randcoef(gfield)
        newval = polynomial(randval)%gfield
        if (randval, newval) not in shares:
            shares.append((randval, newval))
    return shares

def reconstruct_secret(shares, threshold, gfield):
    """ reconstruct the secret from a set of shares """
    secret = 0

    if len(shares) < threshold:
        raise Exception()  # TODO

    for share_out in shares:
        x_out, y_out = share_out
        num = int(y_out)
        den = 1

        for share_in in shares:
            x_in, y_in = share_in
            if x_out != x_in:
                num *= x_in
                den *= (x_in-x_out)

        fraction = Fraction(num, den)  # reduce to lowest terms
        num = fraction.numerator
        den = fraction.denominator

        # modular fraction
        modfraction = (num*pow(den, -1, mod=gfield))%gfield

        secret += modfraction

    return secret%gfield

# TODO scramble_fx
# future improvement (cf. key-based steganography), mix the INDEX table order according to some cipher
# in order to minimize pattern detection between similar conf in different comms

A85_INDEX = dict(
    enumerate(
        [
            chr(i) for i in range(33, 118)
        ]
    )
) | {85: 'MESSAGE_ENDING_CHAR'}

B16_INDEX = dict(
    enumerate(
        string.digits+'ABCDEF'
    )
) | {16: 'MESSAGE_ENDING_CHAR'}

B32_INDEX = dict(
    enumerate(
        string.ascii_uppercase+'234567='
    )
) | {33: 'MESSAGE_ENDING_CHAR'}

B64_INDEX = dict(
    enumerate(
        string.ascii_letters+string.digits+'+/='
    )
) | {65: 'MESSAGE_ENDING_CHAR'}

# TODO: to be improved using pydantic (dynamic class loading ?)

A85_CONF = {
    "gfield": 89,
    "table": A85_INDEX,
    "data_encode_fx": base64.a85encode,
    "data_decode_fx": base64.a85decode,
}

B16_CONF = {
    "gfield" : 19,
    "table": B16_INDEX,
    "data_encode_fx": base64.b16encode,
    "data_decode_fx": base64.b16decode,
}

B32_CONF = {
    "gfield": 37,
    "table": B32_INDEX,
    "data_encode_fx": base64.b32encode,
    "data_decode_fx": base64.b32decode,
}

B64_CONF = {
    "gfield" : 67,
    "table": B64_INDEX,
    "data_encode_fx": base64.b64encode,
    "data_decode_fx": base64.b64decode,
}

CODING_MAP = {
    "a85": A85_CONF,
    "b16": B16_CONF,
    "b32": B32_CONF,
    "b64": B64_CONF,
}

def char_encode(char, threshold, shares_num, gfield, table):
    """ turn a single char into a set of shares """
    table = {val: key for key, val in table.items()}

    secret = table[char]
    if secret >= gfield:
        raise Exception("")  # TODO

    poly = gen_polynomial(secret, threshold, gfield)
    shares = gen_shares(poly, shares_num, gfield)

    return shares

def char_decode(shares, threshold, gfield, table):
    """ reconstruct a single char from a set of shares """
    value = reconstruct_secret(shares, threshold, gfield)
    value = table[value]

    return value

def data_input(bstring, threshold, shares_num, confkey):
    """
    turns a bytes-like object into a list of shares
    according to the configuration of confkey
    """
    conf = CODING_MAP[confkey]

    gfield = conf["gfield"]
    table = conf["table"]
    data_encode_fx = conf["data_encode_fx"]

    data = data_encode_fx(bstring)

    list_of_shares = []
    for value in data:
        value = chr(value)
        shares = char_encode(value, threshold, shares_num, gfield, table)
        list_of_shares.append(shares)

    return list_of_shares

def data_output(list_of_shares, threshold, confkey):
    """
    turns a list of shares into a bytes-like object
    according to the configuration of confkey
    """
    conf = CODING_MAP[confkey]

    gfield = conf["gfield"]
    table = conf["table"]
    data_decode_fx = conf["data_decode_fx"]

    data = ""
    for shares in list_of_shares:
        data += char_decode(shares, threshold, gfield, table)

    data = data_decode_fx(data)

    return data
