package sample;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SensitiveLoggingExample {
    private static final Logger log =
        LoggerFactory.getLogger(SensitiveLoggingExample.class);

    public void login(String userId, String password) {
        log.info("Login attempt userId={}, password={}", userId, password);
    }
}
