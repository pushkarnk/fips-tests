import java.util.Arrays;
import java.security.*;
import java.security.DrbgParameters;
import java.security.DrbgParameters.Instantiation;
import java.security.DrbgParameters.Capability;
import java.lang.Long;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SecureRandomTest {
    private static void testArrayInequality(byte[] a, byte[] b) {
        Utils.assertFalse("Consecutive calls generated equal arrays", Arrays.equals(a, b));
    }

    public static void testDRBGCreation() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512","OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", "OpenSSLFIPSProvider");

        Utils.assertIntEquals("Invalid seed length [CTR]", ctr.generateSeed(8).length, 8);
        Utils.assertIntEquals("Invalid seed length [HMAC]", hmac.generateSeed(8).length, 8);
        Utils.assertIntEquals("Invalid seed length [HASH]", hash.generateSeed(8).length, 8);

    }

    public static void testDRBGCreationWithParams() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandomParameters params = DrbgParameters.instantiation(144, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", params, "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512", params, "OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", params, "OpenSSLFIPSProvider");

        Utils.assertIntEquals("Invalid seed length [CTR]", ctr.generateSeed(8).length, 8);
        Utils.assertIntEquals("Invalid seed length [HMAC]", hmac.generateSeed(8).length, 8);
        Utils.assertIntEquals("Invalid seed length [HASH]", hash.generateSeed(8).length, 8);

    }

    public static void testDRBGCreationGenerateSeed() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512","OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", "OpenSSLFIPSProvider");

        testArrayInequality(ctr.generateSeed(8), ctr.generateSeed(8));
        testArrayInequality(hmac.generateSeed(16), hmac.generateSeed(16));
        testArrayInequality(hash.generateSeed(32), hash.generateSeed(32));

    }

    public static void testDRBGCreationWithParamsGenerateSeed() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandomParameters params = DrbgParameters.instantiation(144, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512","OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", "OpenSSLFIPSProvider");

        testArrayInequality(ctr.generateSeed(8), ctr.generateSeed(8));
        testArrayInequality(hmac.generateSeed(16), hmac.generateSeed(16));
        testArrayInequality(hash.generateSeed(32), hash.generateSeed(32));

    }

    public static void testDRBGCreationNextBytes() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512","OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", "OpenSSLFIPSProvider");

        byte [] ctr1 = new byte[32];
        byte [] ctr2 = new byte[32];
        ctr.nextBytes(ctr1);
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[64];
        byte [] hmac2 = new byte[64];
        hmac.nextBytes(hmac1);
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[64];
        byte [] hash2 = new byte[64];
        hash.nextBytes(hash1);
        hash.nextBytes(hash2);

        testArrayInequality(ctr1, ctr2);
        testArrayInequality(hmac1, hmac2);
        testArrayInequality(hash1, hash2);

    }

    public static void testDRBGCreationWithParamsNextBytes() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandomParameters params = DrbgParameters.instantiation(256, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());

        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", params, "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512", params, "OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", params, "OpenSSLFIPSProvider");

        // TODO: size > 92 fails at openssl level, sometimes malloc() fails
        byte [] ctr1 = new byte[32];
        byte [] ctr2 = new byte[32];
        ctr.nextBytes(ctr1);
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[64];
        byte [] hmac2 = new byte[64];
        hmac.nextBytes(hmac1);
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[84];
        byte [] hash2 = new byte[84];
        hash.nextBytes(hash1);
        hash.nextBytes(hash2);

        testArrayInequality(ctr1, ctr2);
        testArrayInequality(hmac1, hmac2);
        testArrayInequality(hash1, hash2);

    }

    public static void testDRBGCreationNextBytesWithParams() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandomParameters nbParams = DrbgParameters.nextBytes(256, false, "123456".getBytes());

        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512","OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", "OpenSSLFIPSProvider");

        // TODO: memory corruption for next byte array sizes >= 32
        byte [] ctr1 = new byte[8];
        byte [] ctr2 = new byte[8];
        ctr.nextBytes(ctr1, nbParams);
        ctr.nextBytes(ctr2, nbParams);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1, nbParams);
        hmac.nextBytes(hmac2, nbParams);

        byte [] hash1 = new byte[32];
        byte [] hash2 = new byte[32];
        hash.nextBytes(hash1, nbParams);
        hash.nextBytes(hash2, nbParams);

        testArrayInequality(ctr1, ctr2);
        testArrayInequality(hmac1, hmac2);
        testArrayInequality(hash1, hash2);

    }

    public static void testDRBGCreationWithParamsNextBytesWithParams() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        SecureRandomParameters nbParams = DrbgParameters.nextBytes(128, true, "ADDITIONALINPUT".getBytes());

        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", params, "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512", params, "OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", params, "OpenSSLFIPSProvider");

        byte [] ctr1 = new byte[32];
        byte [] ctr2 = new byte[32];
        ctr.nextBytes(ctr1, nbParams);
        ctr.nextBytes(ctr2, nbParams);

        byte [] hmac1 = new byte[32];
        byte [] hmac2 = new byte[32];
        hmac.nextBytes(hmac1, nbParams);
        hmac.nextBytes(hmac2, nbParams);

        byte [] hash1 = new byte[32];
        byte [] hash2 = new byte[32];
        hash.nextBytes(hash1, nbParams);
        hash.nextBytes(hash2, nbParams);

        testArrayInequality(ctr1, ctr2);
        testArrayInequality(hmac1, hmac2);
        testArrayInequality(hash1, hash2);

    }

    public static void testDRBGCreationReseed() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512","OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", "OpenSSLFIPSProvider");

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[32];
        ctr.nextBytes(ctr1);
        ctr.reseed();
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.reseed();
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.reseed();
        hash.nextBytes(hash2);

        testArrayInequality(ctr1, ctr2);
        testArrayInequality(hmac1, hmac2);
        testArrayInequality(hash1, hash2);

    }

    public static void testDRBGCreationWithParamsReseed() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", params, "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512", params, "OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", params, "OpenSSLFIPSProvider");

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.nextBytes(ctr1);
        ctr.reseed();
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.reseed();
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.reseed();
        hash.nextBytes(hash2);

        testArrayInequality(ctr1, ctr2);
        testArrayInequality(hmac1, hmac2);
        testArrayInequality(hash1, hash2);


    }

    public static void testDRBGCreationReseedWithParams() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512","OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", "OpenSSLFIPSProvider");

        SecureRandomParameters rs = DrbgParameters.reseed(true, "ADDITIONALINPUT".getBytes());
        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.nextBytes(ctr1);
        ctr.reseed(rs);
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.reseed(rs);
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.reseed(rs);
        hash.nextBytes(hash2);

        testArrayInequality(ctr1, ctr2);
        testArrayInequality(hmac1, hmac2);
        testArrayInequality(hash1, hash2);


    }

    public static void testDRBGCreationWithParamsReseedWithParams() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", params, "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512", params, "OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", params, "OpenSSLFIPSProvider");

        SecureRandomParameters rs = DrbgParameters.reseed(true, "ADDITIONALINPUT".getBytes());
        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.nextBytes(ctr1);
        ctr.reseed(rs);
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.reseed(rs);
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.reseed(rs);
        hash.nextBytes(hash2);

        testArrayInequality(ctr1, ctr2);
        testArrayInequality(hmac1, hmac2);
        testArrayInequality(hash1, hash2);


    }

    public static void testDRBGCreationSetSeedBytes() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512","OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", "OpenSSLFIPSProvider");

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.nextBytes(ctr1);
        ctr.setSeed("NEWBYTES".getBytes());
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.setSeed("NEWBYTES".getBytes());
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.setSeed("NEWBYTES".getBytes());
        hash.nextBytes(hash2);

        testArrayInequality(ctr1, ctr2);
        testArrayInequality(hmac1, hmac2);
        testArrayInequality(hash1, hash2);

    }

    public static void testDRBGCreationWithParamsSetSeedBytes() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", params, "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512", params, "OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", params, "OpenSSLFIPSProvider");

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.nextBytes(ctr1);
        ctr.setSeed("NEWBYTES".getBytes());
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.setSeed("NEWBYTES".getBytes());
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.setSeed("NEWBYTES".getBytes());
        hash.nextBytes(hash2);

        testArrayInequality(ctr1, ctr2);
        testArrayInequality(hmac1, hmac2);
        testArrayInequality(hash1, hash2);

    }

    public static void testDRBGCreationSetSeedLong() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512","OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", "OpenSSLFIPSProvider");

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.nextBytes(ctr1);
        ctr.setSeed(Long.MAX_VALUE);
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.setSeed(Long.MAX_VALUE);
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.setSeed(Long.MAX_VALUE);
        hash.nextBytes(hash2);

        testArrayInequality(ctr1, ctr2);
        testArrayInequality(hmac1, hmac2);
        testArrayInequality(hash1, hash2);

    }

    public static void testDRBGCreationWithParamsSetSeedLong() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandomParameters params = DrbgParameters.instantiation(128, Capability.PR_AND_RESEED, "FIPSPROTOTYPE".getBytes());
        SecureRandom ctr = SecureRandom.getInstance("AES256CTR", params, "OpenSSLFIPSProvider");
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512", params, "OpenSSLFIPSProvider");
        SecureRandom hash = SecureRandom.getInstance("HMACSHA256", params, "OpenSSLFIPSProvider");

        byte [] ctr1 = new byte[16];
        byte [] ctr2 = new byte[16];
        ctr.nextBytes(ctr1);
        ctr.setSeed(Long.MAX_VALUE);
        ctr.nextBytes(ctr2);

        byte [] hmac1 = new byte[16];
        byte [] hmac2 = new byte[16];
        hmac.nextBytes(hmac1);
        hmac.setSeed(Long.MAX_VALUE);
        hmac.nextBytes(hmac2);

        byte [] hash1 = new byte[16];
        byte [] hash2 = new byte[16];
        hash.nextBytes(hash1);
        hash.setSeed(Long.MAX_VALUE);
        hash.nextBytes(hash2);

        testArrayInequality(ctr1, ctr2);
        testArrayInequality(hmac1, hmac2);
        testArrayInequality(hash1, hash2);

    }

    public static void main(String[] args) throws Exception {
        System.out.print("SecureRandomTest: ");
        testDRBGCreation();
        testDRBGCreationWithParams();
        testDRBGCreationGenerateSeed();
        testDRBGCreationWithParamsGenerateSeed();
        testDRBGCreationNextBytes();
        testDRBGCreationWithParamsNextBytes();
        testDRBGCreationNextBytesWithParams();
        testDRBGCreationWithParamsNextBytesWithParams();
        testDRBGCreationReseed();
        testDRBGCreationWithParamsReseed();
        testDRBGCreationReseedWithParams();
        testDRBGCreationWithParamsReseedWithParams();
        testDRBGCreationSetSeedBytes();
        testDRBGCreationWithParamsSetSeedBytes();
        testDRBGCreationSetSeedLong();
        testDRBGCreationWithParamsSetSeedLong();
        System.out.println("DONE");
    }
}