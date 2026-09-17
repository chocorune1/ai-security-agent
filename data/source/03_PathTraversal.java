package sample;

import java.nio.file.*;

public class PathTraversalExample {
    public byte[] download(String fileName) throws Exception {
        Path uploadDir = Paths.get("/app/uploads");
        Path target = uploadDir.resolve(fileName);
        return Files.readAllBytes(target);
    }
}
