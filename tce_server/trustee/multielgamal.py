from random import SystemRandom

# References:
# Rabin & Thorpe, Time-Lapse Cryptography (2006), http://www.eecs.harvard.edu/~cat/tlc.pdf

def modular_product(items, modulo):
    return reduce(lambda x, y: (x*y) % modulo, items, 1)

class MultiElGamal(object):
    def __init__(self, p, g):
        self.p = p
        self.q = (p-1)/2
        self.g = g
        self.random_source = SystemRandom()

    def generate_private_key(self):
        return self.random_source.randint(2, self.q - 1)

    def generate_public_key(self, x):
        return pow(self.g, x, self.p)

    def generate_shares(self, x, share_count, recovery_threshold):
        # generate a list of coefficients, of length recovery_threshold, in the form:
        #  [x, randint(0, q - 1), randint(0, q - 1) ...]
        coefficients = [x] + [self.random_source.randint(0, self.q - 1) for _ in range(recovery_threshold - 1)]

        # use the coefficients to construct a polynomial, of degree recovery_threshold - 1,
        # with y-intercept of x, in the form:
        #  coefficients[0] * i ^ 0 + coefficients[1] * i ^ 1 + coefficients[2] * i ^ 2 ...
        def recovery_polynomial(i):
            return sum(coefficient * pow(i, j) for j, coefficient in enumerate(coefficients))

        # generate shares, in the form:
        #  [recovery_polynomial(1), recovery_polynomial(2), ..., recovery_polynomial(share_count)]
        shares = [recovery_polynomial(i+1) for i in range(share_count)]

        # generate commitments for each random coefficient, in the form:
        #  [g ^ coefficients[1] % p, g ^ coefficients[2] % p ...]
        commitments = [pow(self.g, coefficient, self.p) for coefficient in coefficients[1:]]

        return shares, commitments, coefficients

    def confirm_share(self, share_input, share_output, commitments):
        secret_share_check = pow(self.g, share_output, self.p)
        commitment_check = modular_product(
            (pow(commitment, pow(share_input, i), self.p) for i, commitment in
             enumerate(commitments)), self.p)
        return secret_share_check == commitment_check

    def combine_public_keys(self, y_list):
        return modular_product([y for y in y_list], self.p)