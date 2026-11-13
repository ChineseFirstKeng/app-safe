package example.nativefixture;

public final class Entry extends android.app.Activity {
    public static String endpoint() {
        return helper("fixture-java-literal");
    }
    public static String helper(String value) {
        return value.trim();
    }
    public static int helper(int value) {
        return value + 7;
    }
    public static boolean numericGate(int value) {
        return value == 123456;
    }
}
