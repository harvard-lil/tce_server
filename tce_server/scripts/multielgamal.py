import logging
from random import SystemRandom
import itertools

from secretsharing import modular_lagrange_interpolation
### References:

# Rabin-Thorpe: Rabin & Thorpe, Time-Lapse Cryptography (2006), http://www.eecs.harvard.edu/~cat/tlc.pdf

def modular_product(items, modulo):
    return reduce(lambda x, y: (x*y) % modulo, items, 1)

class MultiElGamal(object):
    def __init__(self, p, g):
        self.p = p
        self.q = (p-1)/2
        self.g = g

    def generate_private_key(self):
        random_source = SystemRandom()

        x = random_source.randint(2, self.q - 1)
        y = pow(self.g, x, self.p)

        return x, y

    def generate_shares(self, x, share_count, recovery_threshold):
        random_source = SystemRandom()

        coefficients = [x] + [random_source.randint(0, self.q - 1) for _ in range(recovery_threshold - 1)]
        shares = [(i, (sum(coefficient * pow(i, j) for j, coefficient in enumerate(coefficients)))) for i in range(1, share_count+1)]
        commitments = [pow(self.g, coefficient, self.p) for coefficient in coefficients]

        return shares, commitments

    def confirm_share(self, share_input, share_output, commitments):
        secret_share_check = pow(self.g, share_output, self.p)
        commitment_check = modular_product(
            (pow(commitment, pow(share_input, i), self.p) for i, commitment in
             enumerate(commitments)), self.p)
        return secret_share_check == commitment_check

    def combine_public_keys(self, y_list):
        return modular_product([y for y in y_list], self.p)

    def recover_private_key(self, y, shares, recovery_threshold):
        x_shares = []

        for x_share, polynomial_points in shares:

            x_options = set()

            if x_share is not None:
                x_options.add(x_share)

            if len(polynomial_points) >= recovery_threshold:
                for point_subset in itertools.combinations(polynomial_points, recovery_threshold):
                    x_options.add(modular_lagrange_interpolation(0, list(point_subset), self.q))

            if not x_options:
                raise ValueError("Failed to recover key -- not enough shares available.")
            elif len(x_options) > 1:
                logging.warning("Polynomial points resulted in multiple possible x shares -- checking all.")

            x_shares.append(x_options)

        for x_combo in itertools.product(*x_shares):
            x = sum(x_combo)
            if pow(self.g, x, self.p) == y:
                return x

        raise ValueError("Failed to recover key -- regenerated x did not match known y value.")