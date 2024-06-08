#!/usr/bin/python3

from fractions import Fraction
import secrets

from numpy.polynomial import Polynomial as P


def randcoef(gfield):
    """ generate a random coefficient between 1 and gfield-1"""
    return secrets.randbelow(gfield-2)+1

def gen_coefs(threshold, gfield):
    """ generate the coefficients for the polynomial beyond the 0th degree """
    return [randcoef(gfield) for k in range(threshold-1)]

def gen_polynomial(secret, threshold, gfield):
    """ """
    coefs = [secret]
    coefs.extend(gen_coefs(threshold, gfield))
    polynomial = P(coefs)
    return polynomial

def gen_shares(polynomial, shares_num, gfield):
    """ """
    shares = []
    while len(shares)<shares_num:
        randval = randcoef(gfield)
        newval = polynomial(randval)%gfield
        if (randval, newval) not in shares:
            shares.append((randval, newval))
    return shares

def reconstruct_secret(shares, threshold, gfield):
    """ """
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
