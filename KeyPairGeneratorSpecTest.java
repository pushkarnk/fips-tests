import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

public class KeyPairGeneratorSpecTest {

    private static KeyPairGenerator ec() throws Exception {
        return KeyPairGenerator.getInstance("EC", "OpenSSLFIPSProvider");
    }

    private static KeyPairGenerator dh() throws Exception {
        return KeyPairGenerator.getInstance("DH", "OpenSSLFIPSProvider");
    }

    private static void assertCurveAcceptedAndGenerates(String curveName) throws Exception {
        KeyPairGenerator kpg = ec();
        kpg.initialize(new ECGenParameterSpec(curveName));
        KeyPair kp = kpg.generateKeyPair();
        Utils.assertNotNull("Null KeyPair for " + curveName, kp);
        Utils.assertNotNull("Null private key for " + curveName, kp.getPrivate());
        Utils.assertNotNull("Null public key for " + curveName, kp.getPublic());
    }

    public static void ecAcceptsCanonicalOpenSSLName_P256() throws Exception {
        assertCurveAcceptedAndGenerates("prime256v1");
    }

    public static void ecAcceptsSecName_P256() throws Exception {
        assertCurveAcceptedAndGenerates("secp256r1");
    }

    public static void ecAcceptsPName_P256() throws Exception {
        assertCurveAcceptedAndGenerates("P-256");
    }

    public static void ecAcceptsNistName_P256() throws Exception {
        assertCurveAcceptedAndGenerates("NIST P-256");
    }

    public static void ecAcceptsSecName_P384() throws Exception {
        assertCurveAcceptedAndGenerates("secp384r1");
    }

    public static void ecAcceptsPName_P384() throws Exception {
        assertCurveAcceptedAndGenerates("P-384");
    }

    public static void ecAcceptsNistName_P384() throws Exception {
        assertCurveAcceptedAndGenerates("NIST P-384");
    }

    public static void ecAcceptsSecName_P521() throws Exception {
        assertCurveAcceptedAndGenerates("secp521r1");
    }

    public static void ecAcceptsPName_P521() throws Exception {
        assertCurveAcceptedAndGenerates("P-521");
    }

    public static void ecAcceptsNistName_P521() throws Exception {
        assertCurveAcceptedAndGenerates("NIST P-521");
    }

    public static void ecRejectsUnsupportedCurve() throws Exception {
        try {
            ec().initialize(new ECGenParameterSpec("secp192r1"));
            Utils.fail("expected InvalidAlgorithmParameterException for unsupported curve");
        } catch (InvalidAlgorithmParameterException expected) {
        }
    }

    public static void ecRejectsNonECGenParameterSpec() throws Exception {
        try {
            ec().initialize(new IvParameterSpec(new byte[16]));
            Utils.fail("expected InvalidAlgorithmParameterException for non-ECGenParameterSpec");
        } catch (InvalidAlgorithmParameterException expected) {
        }
    }

    public static void dhRejectsDHParameterSpec() throws Exception {
        BigInteger p = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
            + "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
            + "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
            + "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
            + "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
            + "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16);
        BigInteger g = BigInteger.valueOf(2);
        try {
            dh().initialize(new DHParameterSpec(p, g));
            Utils.fail("expected InvalidAlgorithmParameterException for DHParameterSpec");
        } catch (InvalidAlgorithmParameterException expected) {
        }
    }

    public static void ecKeysizeStillWorks() throws Exception {
        KeyPairGenerator kpg = ec();
        kpg.initialize(384);
        Utils.assertNotNull("Null KeyPair for EC keysize 384", kpg.generateKeyPair());
    }

    public static void dhKeysizeStillWorks() throws Exception {
        KeyPairGenerator kpg = dh();
        kpg.initialize(2048);
        Utils.assertNotNull("Null KeyPair for DH keysize 2048", kpg.generateKeyPair());
    }

    public static void ecKeysizeUnsupportedThrows() {
        try {
            ec().initialize(123);
            Utils.fail("expected IllegalArgumentException for unsupported EC keysize");
        } catch (IllegalArgumentException expected) {
        } catch (Exception e) {
            Utils.fail("expected IllegalArgumentException, got " + e.getClass().getName());
        }
    }

    public static void dhKeysizeUnsupportedThrows() {
        try {
            dh().initialize(1024);
            Utils.fail("expected IllegalArgumentException for unsupported DH keysize");
        } catch (IllegalArgumentException expected) {
        } catch (Exception e) {
            Utils.fail("expected IllegalArgumentException, got " + e.getClass().getName());
        }
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new OpenSSLFIPSProvider());
        System.out.print("KeyPairGeneratorSpecTest: ");
        ecAcceptsCanonicalOpenSSLName_P256();
        ecAcceptsSecName_P256();
        ecAcceptsPName_P256();
        ecAcceptsNistName_P256();
        ecAcceptsSecName_P384();
        ecAcceptsPName_P384();
        ecAcceptsNistName_P384();
        ecAcceptsSecName_P521();
        ecAcceptsPName_P521();
        ecAcceptsNistName_P521();
        ecRejectsUnsupportedCurve();
        ecRejectsNonECGenParameterSpec();
        dhRejectsDHParameterSpec();
        ecKeysizeStillWorks();
        dhKeysizeStillWorks();
        ecKeysizeUnsupportedThrows();
        dhKeysizeUnsupportedThrows();
        System.out.println("DONE");
    }
}
