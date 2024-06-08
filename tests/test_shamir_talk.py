from anansi.shamir_talk import gen_polynomial, gen_shares, reconstruct_secret

secret = 7
threshold = 3
gfield = 19

p = gen_polynomial(secret, threshold, gfield)
shares = gen_shares(p, 5, gfield)

print(shares)
new_secret = reconstruct_secret(shares, threshold, gfield)
print(new_secret)
print(secret==new_secret)
