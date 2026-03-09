import java.nio.ByteBuffer;
import java.security.DigestException;
import java.util.Arrays;
import java.util.function.*;
import java.util.List;
import java.security.Security;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class MDTest {

    private static byte[] input = """
       From that time on, the world was hers for the reading.
       She would never be lonely again, never miss the lack of intimate friends.
       Books became her friends and there was one for every mood.""".getBytes();

    private static byte[] input1 = """
       From that time on, the world was hers for the reading.
       She would never be lonely again, never miss the lack of intimate friends.
       Books became her friends and there was one for every mood""".getBytes();

    private static BiFunction<MessageDigest, byte[], byte[]> mdCompute = (md, input) -> {
        md.update(input, 0, input.length);
        return md.digest();
    };

    public static void messageDigestTest() throws Exception {
        for (String name : List.of("MDSHA1", "MDSHA224", "MDSHA3_384", "MDSHA3_512")) {
            MessageDigest md1 = MessageDigest.getInstance(name, "OpenSSLFIPSProvider");
            MessageDigest md2 = MessageDigest.getInstance(name, "OpenSSLFIPSProvider");
            MessageDigest md3 = MessageDigest.getInstance(name, "OpenSSLFIPSProvider");
            byte[] output1 = mdCompute.apply(md1, input);
            byte[] output2 = mdCompute.apply(md2, input);
            byte[] output3 = mdCompute.apply(md3, input1);
            Utils.assertArrayEquals("Test for Message Digest "  + name + " failed.", output1, output2);
            Utils.assertFalse("Test for Message Digest " + name + " failed.", Arrays.equals(output2, output3));
        }
    }

    public static void messageDigestElaborateTest() throws Exception {
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512","OpenSSLFIPSProvider");
        for (String name: List.of("MDSHA1", "MDSHA224", "MDSHA3_384", "MDSHA3_512")) {
            byte[] bytes1 = new byte[10240];
            hmac.nextBytes(bytes1);

            byte[] bytes2 = new byte[10240];
            hmac.nextBytes(bytes2);

            byte[] bytes3 = new byte[20480];
            hmac.nextBytes(bytes3);

            byte[] bytes4 = new byte[10240];
            hmac.nextBytes(bytes4);

            MessageDigest md = MessageDigest.getInstance(name, "OpenSSLFIPSProvider");

            // update 1
            for (byte b : bytes1) {
                md.update(b);
            }

            // update 2
            md.update(bytes2);

            // update 3
            md.update(bytes3, 100, 10240);

            // update 4
            md.update(ByteBuffer.wrap(bytes4));

            // get digest
            byte[] digest1 = md.digest();

            // reset
            md.reset();

            // update 1
            md.update(ByteBuffer.wrap(bytes1));

            // update 2
            for (byte b : bytes2) {
                md.update(b);
            }

            // update 3
            md.update(bytes3, 100, 10240);

            // update 4 and get digest
            byte[] digest2 = md.digest(bytes4);

            Utils.assertIntEquals("Elaborate test for Message Digest " + name + " failed.", md.getDigestLength(), digest2.length);
            Utils.assertTrue("Elaborate test for Message Digest " + name + " failed.", MessageDigest.isEqual(digest1, digest2));

        }
    }

    public static void main(String[] args) throws Exception {
        System.out.print("MDTest: ");
        messageDigestTest();
        messageDigestElaborateTest();
        System.out.println("DONE");
    }
}