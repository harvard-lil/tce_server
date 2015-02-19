package edu.harvard.law.lil;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.ElGamalPublicBCPGKey;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.*;


public class KeyFileTool
{
    /*
        Write the given keyring to a file.
    */
    private static void writeKeyRing(
            PGPKeyRing keyRing,
            String path)
            throws IOException
    {
        OutputStream out = new ArmoredOutputStream(new FileOutputStream(path));
        keyRing.encode(out);
        out.close();
    }

    /*
        Given an existing DSA signing key and ElGamal params, return a key ring generator with that ElGamal subkey attached.
    */
    private static PGPKeyRingGenerator keyRingWithElGamalParams(
            PGPKeyPair dsaKeyPair,
            String identity,
            BigInteger p,
            BigInteger g,
            BigInteger x,
            BigInteger y
            )
            throws PGPException
    {
        ElGamalParameters egp = new ElGamalParameters(p, g);
        PGPKeyPair elgKeyPair = new BcPGPKeyPair(
                PGPPublicKey.ELGAMAL_ENCRYPT,
                new AsymmetricCipherKeyPair(new ElGamalPublicKeyParameters(y, egp), new ElGamalPrivateKeyParameters(x, egp)),
                dsaKeyPair.getPublicKey().getPublicKeyPacket().getTime());

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        // We use a blank password because BouncyCastle seems to generate non-valid keys if there's no password.
        PBESecretKeyEncryptor blankEncryptor = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build("".toCharArray());
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                dsaKeyPair,
                identity,
                sha1Calc,
                null,
                null,
                new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                blankEncryptor);

        keyRingGen.addSubKey(elgKeyPair);

        return keyRingGen;
    }

    public static void main(
            String[] args)
            throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        if(args[0].equals("create")) {
            /*
                In "create" mode, we create a new random DSA signing key, with the given public ElGamal params as a subkey.
                We use a dummy value for the private ElGamal x value.
            */

            if (args.length != 7) {
                System.out.println("create p g y secret_key_file public_key_file name");
                System.exit(0);
            }

            // generate random DSA master key
            KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", "BC");
            dsaKpg.initialize(1024);
            KeyPair dsaKp = dsaKpg.generateKeyPair();
            PGPKeyPair        dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());

            // add ElGamal subkey
            PGPKeyRingGenerator keyRingGen = keyRingWithElGamalParams(
                    dsaKeyPair,
                    args[6],
                    new BigInteger(args[1], 16),
                    new BigInteger(args[2], 16),
                    new BigInteger("1", 16),  // dummy
                    new BigInteger(args[3], 16)
            );

            // export files
            writeKeyRing(keyRingGen.generateSecretKeyRing(), args[4]);
            writeKeyRing(keyRingGen.generatePublicKeyRing(), args[5]);

        }else if(args[0].equals("add")){
            /*
                In "add" mode, we export a modified version of the given private key,
                where the ElGamal subkey is modified to use the given x value.
             */

            if (args.length != 4) {
                System.out.println("add old_secret_key_file x new_secret_key_file");
                System.exit(0);
            }

            // read keyring
            InputStream keyIn = new BufferedInputStream(new FileInputStream(args[1]));
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing)pgpSec.getKeyRings().next();
            Iterator keyIter = keyRing.getSecretKeys();

            // read DSA secret key, and convert to a PGPKeyPair for re-export
            PGPSecretKey dsaSecretKey = (PGPSecretKey)keyIter.next();
            PGPPrivateKey dsaPriv = dsaSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("".toCharArray()));
            PGPPublicKey dsaPub = dsaSecretKey.getPublicKey();
            PGPKeyPair dsaKeyPair = new PGPKeyPair(dsaPub, dsaPriv);

            // read ElGamal subkey
            PGPSecretKey oldElgKeyPair = (PGPSecretKey)keyIter.next();
            PGPPublicKey elgPub = oldElgKeyPair.getPublicKey();
            ElGamalPublicBCPGKey packet = (ElGamalPublicBCPGKey)elgPub.getPublicKeyPacket().getKey();

            // generate modified keyring with existing DSA key and new ElGamal x value
            PGPKeyRingGenerator keyRingGen = keyRingWithElGamalParams(
                    dsaKeyPair,
                    (String) dsaKeyPair.getPublicKey().getUserIDs().next(),
                    packet.getP(),
                    packet.getG(),
                    new BigInteger(args[2], 16),
                    packet.getY()
            );

            // remove the blank password added by keyRingWithElGamalParams
            PGPSecretKeyRing secretKeyRing = PGPSecretKeyRing.copyWithNewPassword(
                    keyRingGen.generateSecretKeyRing(),
                    new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("".toCharArray()),
                    null);

            // export file
            writeKeyRing(secretKeyRing, args[3]);

        }
    }
}
