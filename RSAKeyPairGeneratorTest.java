import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import com.canonical.openssl.key.KeyConverter;

public class RSAKeyPairGeneratorTest {

    private static KeyPairGenerator rsa() throws Exception {
        return KeyPairGenerator.getInstance("RSA");
    }

    // Parse the generated X.509 public key with the JDK to read back the actual
    // modulus size and public exponent the FIPS module produced.
    private static RSAPublicKey parsePublic(KeyPair kp) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(
            new X509EncodedKeySpec(kp.getPublic().getEncoded()));
    }

    private static void assertGeneratesKeyOfSize(KeyPair kp, int expectedBits) throws Exception {
        Utils.assertNotNull("Null KeyPair", kp);
        Utils.assertNotNull("Null private key", kp.getPrivate());
        Utils.assertNotNull("Null public key", kp.getPublic());
        Utils.assertEquals("RSA algorithm (public)", "RSA", kp.getPublic().getAlgorithm());
        Utils.assertEquals("RSA algorithm (private)", "RSA", kp.getPrivate().getAlgorithm());
        Utils.assertEquals("Public key format", "X.509", kp.getPublic().getFormat());
        Utils.assertEquals("Private key format", "PKCS#8", kp.getPrivate().getFormat());

        RSAPublicKey pub = parsePublic(kp);
        Utils.assertIntEquals("Unexpected modulus size", expectedBits, pub.getModulus().bitLength());
        Utils.assertEquals("Unexpected public exponent",
            RSAKeyGenParameterSpec.F4, pub.getPublicExponent());
    }

    public static void defaultGeneratesApproved2048() throws Exception {
        // No initialize() call: must default to a FIPS-approved 2048-bit key.
        assertGeneratesKeyOfSize(rsa().generateKeyPair(), 2048);
    }

    public static void keysizeInit2048() throws Exception {
        KeyPairGenerator kpg = rsa();
        kpg.initialize(2048);
        assertGeneratesKeyOfSize(kpg.generateKeyPair(), 2048);
    }

    public static void keysizeInit3072() throws Exception {
        KeyPairGenerator kpg = rsa();
        kpg.initialize(3072);
        assertGeneratesKeyOfSize(kpg.generateKeyPair(), 3072);
    }

    public static void specInit2048WithF4() throws Exception {
        KeyPairGenerator kpg = rsa();
        kpg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
        assertGeneratesKeyOfSize(kpg.generateKeyPair(), 2048);
    }

    public static void generatedKeysAreFipsDecodable() throws Exception {
        // The generated DER must round-trip back into the OpenSSL FIPS module,
        // proving the keys are usable on the FIPS crypto path (not just by the JDK).
        KeyPair kp = rsa().generateKeyPair();

        long pubHandle = KeyConverter.publicKeyToEVPKey(kp.getPublic());
        Utils.assertTrue("FIPS decode of public key failed", pubHandle != 0);
        KeyConverter.freeEVPKey(pubHandle);

        long privHandle = KeyConverter.privateKeyToEVPKey(kp.getPrivate());
        Utils.assertTrue("FIPS decode of private key failed", privHandle != 0);
        KeyConverter.freeEVPKey(privHandle);
    }

    public static void rejectsUnapprovedKeysize1024() throws Exception {
        try {
            rsa().initialize(1024);
            Utils.fail("expected IllegalArgumentException for unapproved RSA keysize 1024");
        } catch (IllegalArgumentException expected) {
        }
    }

    public static void rejectsSpecKeysize1024() throws Exception {
        try {
            rsa().initialize(new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4));
            Utils.fail("expected InvalidAlgorithmParameterException for RSA spec keysize 1024");
        } catch (InvalidAlgorithmParameterException expected) {
        }
    }

    public static void rejectsTooSmallExponent() throws Exception {
        // e = 3 is below the FIPS 186-5 lower bound of 65537.
        try {
            rsa().initialize(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3)));
            Utils.fail("expected InvalidAlgorithmParameterException for too-small exponent");
        } catch (InvalidAlgorithmParameterException expected) {
        }
    }

    public static void rejectsEvenExponent() throws Exception {
        // 65538 is in range but even; a valid RSA exponent must be odd.
        try {
            rsa().initialize(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(65538)));
            Utils.fail("expected InvalidAlgorithmParameterException for even exponent");
        } catch (InvalidAlgorithmParameterException expected) {
        }
    }

    public static void rejectsNonRSASpec() throws Exception {
        try {
            rsa().initialize(new ECGenParameterSpec("prime256v1"));
            Utils.fail("expected InvalidAlgorithmParameterException for non-RSA spec");
        } catch (InvalidAlgorithmParameterException expected) {
        }
    }

    public static void unapprovedKeysizeThrowsIllegalArgument() {
        try {
            rsa().initialize(2047);
            Utils.fail("expected IllegalArgumentException for unsupported RSA keysize");
        } catch (IllegalArgumentException expected) {
        } catch (Exception e) {
            Utils.fail("expected IllegalArgumentException, got " + e.getClass().getName());
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.print("RSAKeyPairGeneratorTest: ");
        defaultGeneratesApproved2048();
        keysizeInit2048();
        keysizeInit3072();
        specInit2048WithF4();
        generatedKeysAreFipsDecodable();
        rejectsUnapprovedKeysize1024();
        rejectsSpecKeysize1024();
        rejectsTooSmallExponent();
        rejectsEvenExponent();
        rejectsNonRSASpec();
        unapprovedKeysizeThrowsIllegalArgument();
        System.out.println("DONE");
    }
}
