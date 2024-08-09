from anansi.shamir_talk import (
    A85_INDEX,
    B16_INDEX,
    B32_INDEX,
    B64_INDEX,
    data_encoding,
    data_decoding,
    data_input,
    data_output,
    gen_coefs,
    gen_polynomial,
    gen_shares,
    randcoef,
    reconstruct_secret,
)

def test_randcoef():
    """ testing the upper bound of randcoef """
    gfield = 7
    data = randcoef(gfield)
    data < gfield-1

def test_gen_coefs():
    """
    testing the number of coefs generated according to threshold
    and that each coef is unique
    """
    threshold = 4
    gfield = 5
    data = gen_coefs(threshold, gfield)
    len(data) == threshold
    len(data) == len(set(data))

def test_gen_polynomial():
    """
    test the polynomial generated using the secret and threshold,
    the secret should be the first coef
    while the degree should be equal to the threshold
    """
    secret = 3
    threshold = 3
    gfield = 5

    polynomial = gen_polynomial(secret, threshold, gfield)

    polynomial.degree() == threshold
    polynomial.coef[0] == secret

def test_secret_routine():
    """
    round test between embedding and extraction the secret from the polynomial
    """
    secret = 7
    threshold = 3
    gfield = 19

    p = gen_polynomial(secret, threshold, gfield)
    shares = gen_shares(p, 5, gfield)

    new_secret = reconstruct_secret(shares, threshold, gfield)

    secret==new_secret

def test_a85_index():
    """ test the proper on-the-fly generation of the index """
    A85_INDEX == {
        0: '!', 1: '"', 2: '#', 3: '$', 4: '%', 5: '&', 6: "'", 7: '(', 8: ')',
        9: '*', 10: '+', 11: ',', 12: '-', 13: '.', 14: '/', 15: '0', 16: '1',
        17: '2', 18: '3', 19: '4', 20: '5', 21: '6', 22: '7', 23: '8', 24: '9',
        25: ':', 26: ';', 27: '<', 28: '=', 29: '>', 30: '?', 31: '@', 32: 'A',
        33: 'B', 34: 'C', 35: 'D', 36: 'E', 37: 'F', 38: 'G', 39: 'H', 40: 'I',
        41: 'J', 42: 'K', 43: 'L', 44: 'M', 45: 'N', 46: 'O', 47: 'P', 48: 'Q',
        49: 'R', 50: 'S', 51: 'T', 52: 'U', 53: 'V', 54: 'W', 55: 'X', 56: 'Y',
        57: 'Z', 58: '[', 59: '\\', 60: ']', 61: '^', 62: '_', 63: '`', 64: 'a',
        65: 'b', 66: 'c', 67: 'd', 68: 'e', 69: 'f', 70: 'g', 71: 'h', 72: 'i',
        73: 'j', 74: 'k', 75: 'l', 76: 'm', 77: 'n', 78: 'o', 79: 'p', 80: 'q',
        81: 'r', 82: 's', 83: 't', 84: 'u', 85: 'MESSAGE_ENDING_CHAR'
    }

def test_b16_index():
    """ test the proper on-the-fly generation of the index """
    B16_INDEX == {
        0: '0', 1: '1', 2: '2', 3: '3', 4: '4', 5: '5', 6: '6', 7: '7', 8: '8',
        9: '9', 10: 'A', 11: 'B', 12: 'C', 13: 'D', 14: 'E', 15: 'F',
        16: 'MESSAGE_ENDING_CHAR'
    }

def test_b32_index():
    """ test the proper on-the-fly generation of the index """
    B32_INDEX == {
        0: 'A', 1: 'B', 2: 'C', 3: 'D', 4: 'E', 5: 'F', 6: 'G', 7: 'H', 8: 'I',
        9: 'J', 10: 'K', 11: 'L', 12: 'M', 13: 'N', 14: 'O', 15: 'P', 16: 'Q',
        17: 'R', 18: 'S', 19: 'T', 20: 'U', 21: 'V', 22: 'W', 23: 'X', 24: 'Y',
        25: 'Z', 26: '2', 27: '3', 28: '4', 29: '5', 30: '6', 31: '7', 32: '=',
        33: 'MESSAGE_ENDING_CHAR'
    }

def test_b64_index():
    """ test the proper on-the-fly generation of the index """
    B64_INDEX == {
        0: 'a', 1: 'b', 2: 'c', 3: 'd', 4: 'e', 5: 'f', 6: 'g', 7: 'h', 8: 'i',
        9: 'j', 10: 'k', 11: 'l', 12: 'm', 13: 'n', 14: 'o', 15: 'p', 16: 'q',
        17: 'r', 18: 's', 19: 't', 20: 'u', 21: 'v', 22: 'w', 23: 'x', 24: 'y',
        25: 'z', 26: 'A', 27: 'B', 28: 'C', 29: 'D', 30: 'E', 31: 'F', 32: 'G',
        33: 'H', 34: 'I', 35: 'J', 36: 'K', 37: 'L', 38: 'M', 39: 'N', 40: 'O',
        41: 'P', 42: 'Q', 43: 'R', 44: 'S', 45: 'T', 46: 'U', 47: 'V', 48: 'W',
        49: 'X', 50: 'Y', 51: 'Z', 52: '0', 53: '1', 54: '2', 55: '3', 56: '4',
        57: '5', 58: '6', 59: '7', 60: '8', 61: '9', 62: '+', 63: '/', 64: '=',
        65: 'MESSAGE_ENDING_CHAR'
    }

def test_b16_routine():
    """
    round test from input to output for B16 encoding
    """
    list_of_shares = data_input(b"Azerty1234:$", 3, 5, "b16")

    data_output(list_of_shares, 3, "b16") == "Azerty1234:$"

def test_b32_routine():
    """
    round test from input to output for B32 encoding
    """
    list_of_shares = data_input(b"Azerty1234:$", 3, 5, "b32")

    data_output(list_of_shares, 3, "b32") == "Azerty1234:$"

def test_b64_routine():
    """
    round test from input to output for B64 encoding
    """
    list_of_shares = data_input(b"Azerty1234:$", 3, 5, "b64")

    data_output(list_of_shares, 3, "b64") == "Azerty1234:$"

def test_a85_routine():
    """
    round test from input to output for ascii85 encoding
    """
    list_of_shares = data_input(b"Azerty1234:$", 3, 5, "a85")

    data_output(list_of_shares, 3, "a85") == "Azerty1234:$"

def test_data_encoding():
    """
    testing the binary encoding of the data_encoding function
    """
    list_of_shares = [
        [(1,2),(3,4),(5,6)],
        [(1,3),(5,2),(4,6)],
    ]

    data = data_encoding(list_of_shares, 4, "b16")

    value = "000000100010000001100100000010100110010000100011010010100010010010000110"
    data == value

def test_data_decoding():
    """
    testing the binary decoding of the data_decoding function
    """
    data = "000000100010000001100100000010100110010000100011010010100010010010000110"

    list_of_shares = data_decoding(data, 4, "b16")

    value = [
        [(1,2),(3,4),(5,6)],
        [(1,3),(5,2),(4,6)],
    ]
    list_of_shares == value

def test_data_routine():
    """
    round test of data enconding and data decoding function
    """
    data_0 = b"Azerty1234:$"

    list_of_shares_1 = data_input(data_0, 3, 5, "b16")
    data_1 = data_encoding(list_of_shares_1, 4, "b16")
    list_of_shares_2 = data_decoding(data_1, 4, "b16")

    list_of_shares_1==list_of_shares_2

    data_2 = data_output(list_of_shares_2, 3, "b16")

    data_0==data_2
