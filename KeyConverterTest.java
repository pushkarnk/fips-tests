import com.canonical.openssl.key.KeyConverter;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class KeyConverterTest {

    public static void testRSAPrivateKeyConversion() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "OpenSSLFIPSProvider");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        long privateHandle = KeyConverter.privateKeyToEVPKey(kp.getPrivate());
        Utils.assertTrue("Private key conversion should succeed", privateHandle != 0);

        long publicHandle = KeyConverter.publicKeyToEVPKey(kp.getPublic());
        Utils.assertTrue("Public key conversion should succeed", publicHandle != 0);

        KeyConverter.freeEVPKey(privateHandle);
        KeyConverter.freeEVPKey(publicHandle);
    }

    public static void testNullKeyThrowsException() {
        try {
            KeyConverter.privateKeyToEVPKey(null);
            Utils.fail("Should throw IllegalArgumentException for null private key");
        } catch (IllegalArgumentException e) {
            // Expected
        }

        try {
            KeyConverter.publicKeyToEVPKey(null);
            Utils.fail("Should throw IllegalArgumentException for null public key");
        } catch (IllegalArgumentException e) {
            // Expected
        }
    }

    public static void testFreeEVPKeyWithZeroHandle() {
        KeyConverter.freeEVPKey(0);
    }

    public static void testECKeyPairFromFIPSProviderConverts() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "OpenSSLFIPSProvider");
        for (String curve : new String[]{"P-256", "P-384", "P-521"}) {
            kpg.initialize(new ECGenParameterSpec(curve));
            KeyPair kp = kpg.generateKeyPair();

            long privHandle = KeyConverter.privateKeyToEVPKey(kp.getPrivate());
            Utils.assertTrue("EC private key handle must be non-zero for " + curve, privHandle != 0);

            long pubHandle = KeyConverter.publicKeyToEVPKey(kp.getPublic());
            Utils.assertTrue("EC public key handle must be non-zero for " + curve, pubHandle != 0);

            KeyConverter.freeEVPKey(privHandle);
            KeyConverter.freeEVPKey(pubHandle);
        }
    }

    public static void testDHKeyPairFromFIPSProviderConverts() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "OpenSSLFIPSProvider");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        long privHandle = KeyConverter.privateKeyToEVPKey(kp.getPrivate());
        Utils.assertTrue("DH private key handle must be non-zero", privHandle != 0);

        long pubHandle = KeyConverter.publicKeyToEVPKey(kp.getPublic());
        Utils.assertTrue("DH public key handle must be non-zero", pubHandle != 0);

        KeyConverter.freeEVPKey(privHandle);
        KeyConverter.freeEVPKey(pubHandle);
    }

    public static void main(String[] args) throws Exception {
        System.out.print("KeyConverterTest: ");
        testRSAPrivateKeyConversion();
        testNullKeyThrowsException();
        testFreeEVPKeyWithZeroHandle();
        testECKeyPairFromFIPSProviderConverts();
        testDHKeyPairFromFIPSProviderConverts();
        System.out.println("DONE");
    }
}
