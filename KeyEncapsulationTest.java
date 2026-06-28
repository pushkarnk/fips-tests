import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Arrays;
import java.security.KeyPairGenerator;
import javax.crypto.KEM;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.KEM.Encapsulator;
import javax.crypto.KEM.Decapsulator;
import javax.crypto.SecretKey;
import java.security.Security;

public class KeyEncapsulationTest {
    public static void main(String[] args) throws Exception {
        System.out.print("KeyEncapsulationTest: ");
        testKEMRSA();
        testKEMRSAPartialRange();
        System.out.println("DONE");
    }

    public static void testKEMRSA() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "OpenSSLFIPSProvider");
        kpg.initialize(4096);

        // Alice creates a key pair and shares the public key with Bob
        KeyPair aliceKeys = kpg.generateKeyPair();
        PublicKey alicePublicKey = aliceKeys.getPublic();
        PrivateKey alicePrivateKey = aliceKeys.getPrivate();

        // Bob generates a shared secret and wraps it using Alice's public key
        KEM bobKem = KEM.getInstance("RSA", "OpenSSLFIPSProvider");
        Encapsulator encapsulator = bobKem.newEncapsulator(alicePublicKey, null, null);
        int secretSize = encapsulator.secretSize();
        KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, secretSize, "AES");
        SecretKey bobSecret = encapsulated.key();

        // Bob sends the encapsulated secret to Alice
        // Alice uses her RSA private key to unwrap the shared secret
        KEM aliceKem = KEM.getInstance("RSA", "OpenSSLFIPSProvider");
        Decapsulator decapsulator = aliceKem.newDecapsulator(alicePrivateKey, null);
        byte[] encapsulationBytes = encapsulated.encapsulation();
        SecretKey aliceSecret = decapsulator.decapsulate(encapsulationBytes, 0, encapsulationBytes.length, "AES");

        Utils.assertTrue("Key Encapsulation with RSA test failed", aliceSecret.equals(bobSecret));
    }

    public static void testKEMRSAPartialRange() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "OpenSSLFIPSProvider");
        kpg.initialize(4096);

        KeyPair aliceKeys = kpg.generateKeyPair();
        PublicKey alicePublicKey = aliceKeys.getPublic();
        PrivateKey alicePrivateKey = aliceKeys.getPrivate();

        // Bob encapsulates only a sub-range of the shared secret
        KEM bobKem = KEM.getInstance("RSA", "OpenSSLFIPSProvider");
        Encapsulator encapsulator = bobKem.newEncapsulator(alicePublicKey, null, null);
        int secretSize = encapsulator.secretSize();
        int from = 8;
        int to = secretSize / 2;
        KEM.Encapsulated encapsulated = encapsulator.encapsulate(from, to, "AES");
        SecretKey bobSecret = encapsulated.key();

        // The key must only contain the requested slice of the secret
        Utils.assertTrue("Encapsulated key has wrong length for partial range",
                bobSecret.getEncoded().length == to - from);

        // Alice decapsulates the same sub-range and must recover the same key
        KEM aliceKem = KEM.getInstance("RSA", "OpenSSLFIPSProvider");
        Decapsulator decapsulator = aliceKem.newDecapsulator(alicePrivateKey, null);
        byte[] encapsulationBytes = encapsulated.encapsulation();
        SecretKey aliceSecret = decapsulator.decapsulate(encapsulationBytes, from, to, "AES");

        Utils.assertTrue("Decapsulated key has wrong length for partial range",
                aliceSecret.getEncoded().length == to - from);
        Utils.assertTrue("Partial range KEM with RSA test failed", aliceSecret.equals(bobSecret));
    }
}
