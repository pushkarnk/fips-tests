import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.security.KeyPair;
import java.util.Arrays;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.KeyAgreement;

public class KeyAgreementTest {

    public static void main(String[] args) throws Exception {
        System.out.print("KeyAgreementTest: ");
        testDH();
        testECDH();
    }

    private static void runTest(KeyPairGenerator kpg, String algo) throws Exception {
        KeyAgreement aliceAgreement = KeyAgreement.getInstance(algo, "OpenSSLFIPSProvider");
        KeyAgreement bobAgreement = KeyAgreement.getInstance(algo, "OpenSSLFIPSProvider");

        for (int i = 0; i < 2; i++) {
            KeyPair aliceKp = kpg.generateKeyPair();
            KeyPair bobKp = kpg.generateKeyPair();
            aliceAgreement.init(aliceKp.getPrivate());
            aliceAgreement.doPhase(bobKp.getPublic(), true);
            bobAgreement.init(bobKp.getPrivate());
            bobAgreement.doPhase(aliceKp.getPublic(), true);
            byte[] aliceSecret = aliceAgreement.generateSecret();
            byte[] bobSecret = bobAgreement.generateSecret();
            Utils.assertArrayEquals("Key Agreement test for " + algo +  " failed", aliceSecret, bobSecret);

            // make sure generateSecret() resets the KeyAgreement object
            // and can be reused for another agreement
        }
    }

    public static void testDH() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        runTest(kpg, "DH");
    }

    public static void testECDH() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        runTest(kpg, "ECDH");
    }
}
