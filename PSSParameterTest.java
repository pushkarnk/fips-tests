import com.canonical.openssl.provider.OpenSSLFIPSProvider;

import java.security.AlgorithmParameters;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import java.security.InvalidAlgorithmParameterException;

public class PSSParameterTest {

    public static void testExplicitPSSParametersRoundTrip() throws Exception {
        Signature sig = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");

        PSSParameterSpec original = new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        sig.setParameter(original);

        AlgorithmParameters ap = sig.getParameters();
        Utils.assertNotNull("getParameters() must not return null after PSS params are set", ap);

        PSSParameterSpec returned = ap.getParameterSpec(PSSParameterSpec.class);
        Utils.assertEquals("digest algorithm", "SHA-256", returned.getDigestAlgorithm());
        Utils.assertEquals("MGF algorithm", "MGF1", returned.getMGFAlgorithm());
        Utils.assertIntEquals("salt length", 32, returned.getSaltLength());
        Utils.assertIntEquals("trailer field", 1, returned.getTrailerField());

        MGF1ParameterSpec mgf1 = (MGF1ParameterSpec) returned.getMGFParameters();
        Utils.assertNotNull("MGF1 parameters must not be null", mgf1);
        Utils.assertEquals("MGF1 digest", "SHA-256", mgf1.getDigestAlgorithm());
    }

    public static void testMGF1DigestDefaultsToMessageDigest() throws Exception {
        Signature sig = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");

        sig.setParameter(new PSSParameterSpec(20));

        AlgorithmParameters ap = sig.getParameters();
        Utils.assertNotNull("getParameters() must not return null after PSS params are set", ap);

        PSSParameterSpec returned = ap.getParameterSpec(PSSParameterSpec.class);
        Utils.assertEquals("message digest", "SHA-1", returned.getDigestAlgorithm());

        MGF1ParameterSpec mgf1 = (MGF1ParameterSpec) returned.getMGFParameters();
        Utils.assertNotNull("MGF1 parameters must not be null", mgf1);
        Utils.assertEquals("MGF1 digest must default to message digest", "SHA-1", mgf1.getDigestAlgorithm());
    }

    public static void testRejectsNonMGF1Algorithm() throws Exception {
        Signature sig = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        try {
            sig.setParameter(new PSSParameterSpec(
                    "SHA-256", "SHAKE128", MGF1ParameterSpec.SHA256, 32, 1));
            Utils.fail("Expected InvalidAlgorithmParameterException for non-MGF1 MGF");
        } catch (InvalidAlgorithmParameterException expected) {
        }
    }

    public static void testRejectsNonOneTrailerField() throws Exception {
        Signature sig = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        try {
            sig.setParameter(new PSSParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 2));
            Utils.fail("Expected InvalidAlgorithmParameterException for trailerField != 1");
        } catch (InvalidAlgorithmParameterException expected) {
        }
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new OpenSSLFIPSProvider());
        System.out.print("PSSParameterTest: ");
        testExplicitPSSParametersRoundTrip();
        testMGF1DigestDefaultsToMessageDigest();
        testRejectsNonMGF1Algorithm();
        testRejectsNonOneTrailerField();
        System.out.println("DONE");
    }
}
