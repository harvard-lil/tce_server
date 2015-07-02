import unittest2
from trustee.multielgamal import MultiElGamal


class TestMultiElgamal(unittest2.TestCase):
    """
        Test the basic primitives used in ElGamal key generation with verified threshold secret sharing.
    """

    def setUp(self):
        self.p = 921355984572641311672343424898410239406765173564481049529310998437412969038866770004018133863821119723063474210217706973316313378613043770818780115988652746380714841456142639704626352778746695851788302212813071729066781855064705915608677688092341542568424482925462180633889723579377448564293509252435087477281161286147259728549498972138533165527662691306617571151999644107722686129055657829181973528055808318168063541650472028439642172128232391355303186171522887793994216888734434516097403106470551045418225907760866937899119453358993949368302899196593348587781289829114461181435009345801458736138423284445935647778071510107564961338155282235194713303681529865383261800265733083885319259454542964149249843475773904339566680218460878240048849309064731923166303421897726591880342754670170435647389065546266133258192653962148274540863521430747245658342533592543361748499215018089153994702237916350245910933537662925365405565771274120172582583500547352310022433066022690275959677696743489993411404619219133001998952984404232404962367594198986426803887303895347014868878166590277345633941382072502883955197749732581385414098128645307956625290745193548601504669931868639779915942610143766629826114677053173092959998726060927521195420788443
        self.q = (self.p - 1) / 2
        self.g = 5
        self.mg = MultiElGamal(p=self.p, g=self.g)
        self.x = self.mg.generate_private_key()
        self.y = self.mg.generate_public_key(self.x)
        self.shares, self.commitments, self.coefficients = self.mg.generate_shares(self.x, share_count=4, recovery_threshold=3)

    ### generate_private_key ###

    def test_generate_private_key(self):
        # x should be drawn from the range 1 < x < q
        self.assertGreater(self.x, 1)
        self.assertLess(self.x, self.q)

    ### generate_public_key ###

    def test_generate_public_key(self):
        # y should equal g ^ x % p
        self.assertEqual(self.y, pow(self.g, self.x, self.p))

    ### generate_shares ###

    def test_generate_shares(self):
        # check that each commitment i == g ^ coefficient[i] % p
        self.assertListEqual(self.commitments, [
            pow(self.g, self.coefficients[1], self.p),
            pow(self.g, self.coefficients[2], self.p),
        ])

        # check that each share i == poly(i+1)
        self.assertListEqual(self.shares, [
            self.x + self.coefficients[1] * 1 ** 1 + self.coefficients[2] * 1 ** 2,
            self.x + self.coefficients[1] * 2 ** 1 + self.coefficients[2] * 2 ** 2,
            self.x + self.coefficients[1] * 3 ** 1 + self.coefficients[2] * 3 ** 2,
            self.x + self.coefficients[1] * 4 ** 1 + self.coefficients[2] * 4 ** 2,
        ])

    ### confirm_share ###

    def test_confirm_share_all_shares_are_valid(self):
        for i, share in enumerate(self.shares):
            self.assertTrue(self.mg.confirm_share(i+1, share, [self.y]+self.commitments))

    def test_confirm_share_fails_with_wrong_share_input(self):
        self.assertFalse(self.mg.confirm_share(0, self.shares[0], [self.y] + self.commitments))
        self.assertFalse(self.mg.confirm_share(2, self.shares[0], [self.y] + self.commitments))

    def test_confirm_share_fails_with_wrong_share_output(self):
        self.assertFalse(self.mg.confirm_share(1, 0, [self.y] + self.commitments))
        self.assertFalse(self.mg.confirm_share(1, self.shares[0]+1, [self.y] + self.commitments))

    def test_confirm_share_fails_with_wrong_commitments(self):
        self.assertFalse(self.mg.confirm_share(1, self.shares[0], [0] + self.commitments))
        self.commitments[0] += 1
        self.assertFalse(self.mg.confirm_share(1, self.shares[0], [self.y] + self.commitments))

    ### combine_public_keys ###

    def test_combine_public_keys(self):
        # y values should be combined by multiplication % p
        y1 = self.mg.generate_public_key(self.mg.generate_private_key())
        y2 = self.mg.generate_public_key(self.mg.generate_private_key())
        y3 = self.mg.generate_public_key(self.mg.generate_private_key())
        self.assertEqual(self.mg.combine_public_keys([y1, y2, y3]),
                         (y1 * y2 * y3) % self.p)


    ### combine_private_keys ###

    def test_combine_private_keys(self):
        # x values should be combined by summation
        x1 = self.mg.generate_private_key()
        x2 = self.mg.generate_private_key()
        x3 = self.mg.generate_private_key()
        self.assertEqual(self.mg.combine_private_keys([x1, x2, x3]),
                         (x1 + x2 + x3))

    ### recover_private_key ###
