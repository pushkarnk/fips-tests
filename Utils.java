import java.util.Arrays;

public class Utils {
    public static void assertArrayEquals(String message, byte[] expected, byte[] actual) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError(message);
        }
    }

    public static void assertIntEquals(String message, int expected, int actual) {
        if (expected != actual) {
            throw new AssertionError(message);
        }
    }

    public static void assertTrue(String message, boolean condition) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    public static void assertFalse(String message, boolean condition) {
        if (condition) {
            throw new AssertionError(message);
        }
    }

    public static void assertArrayEquals(String message, char[] expected, char[] actual) {
        if (!Arrays.equals(expected, actual)) {
            throw new AssertionError(message);
        }
    }

    public static void assertNotEquals(String message, Object unexpected, Object actual) {
        if (unexpected.equals(actual)) {
            throw new AssertionError(message);
        }
    }

    public static void fail(String message) {
        throw new AssertionError(message);
    }
}