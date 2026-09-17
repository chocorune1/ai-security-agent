package sample;

import java.io.*;

public class CommandInjectionExample {
    public String ping(String host) throws Exception {
        Process process = Runtime.getRuntime().exec("ping -c 1 " + host);
        return new String(process.getInputStream().readAllBytes());
    }
}
