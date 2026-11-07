// SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
public class Main {
    // Vulnerable sample: hardcoded secret assignment.
    private static final String password = "SomeSecret123";

    public static void main(String[] args) {
        System.out.println("password length: " + password.length());
    }
}