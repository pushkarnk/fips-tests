public class Runner {
    public static void main(String[] args) {
        new CipherTest().run();
        new KeyAgreementTest().run();
        new MacTest().run();
        new MDTest().run();
        new SecretKeyFactoryTest().run();
        new SecureRandomTest().run();
    }
}