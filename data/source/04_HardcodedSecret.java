package sample;

public class HardcodedSecretExample {
    private static final String DB_PASSWORD = "SuperSecret123!";
    private static final String API_KEY = "sk-demo-1234567890abcdef";

    public void connect() {
        System.out.println("Connecting with password: " + DB_PASSWORD);
    }
}
