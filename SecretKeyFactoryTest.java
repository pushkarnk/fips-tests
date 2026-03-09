import java.util.Arrays;
import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.InvalidKeyException;
import java.security.Security;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class SecretKeyFactoryTest {
    
    public static void testPBKDF2() throws Exception {
        String password = "Zaq12wsXCde34rfV";
        String salt = "NaClCommonSaltRockSaltSeaSalt";
        int iterationCount = 120000;

        char[] passwordChars = new char[16]; 
        password.getChars(0, 16, passwordChars, 0);
        PBEKeySpec keySpec = new PBEKeySpec(passwordChars, salt.getBytes(), iterationCount);

        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2", "OpenSSLFIPSProvider");
        SecretKey sk1 = pbkdf.generateSecret(keySpec);
        SecretKey sk2 = pbkdf.translateKey(sk1);
        Utils.assertNotEquals("SecretKey is of length 0", sk1.getEncoded().length, 0);
        Utils.assertArrayEquals("Invalid secret key", sk1.getEncoded(), sk2.getEncoded());

        KeySpec spec = pbkdf.getKeySpec(sk2, PBEKeySpec.class);
        Utils.assertTrue("Returned KeySpec is not of the expected type", spec instanceof PBEKeySpec);
        Utils.assertIntEquals("Returned KeySpec does not match original KeySpec", ((PBEKeySpec)spec).getIterationCount(), 120000);
        Utils.assertArrayEquals("Returned KeySpec does not match original KeySpec", ((PBEKeySpec)spec).getPassword(), password.toCharArray());
        Utils.assertArrayEquals("Returned KeySpec does not match original KeySpec", ((PBEKeySpec)spec).getSalt(), salt.getBytes());
    }

    public static void main(String[] args) throws Exception {
        System.out.print("SecretKeyFactoryTest: ");
        testPBKDF2();
    }
}
