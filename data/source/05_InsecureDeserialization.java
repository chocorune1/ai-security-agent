package sample;

import java.io.*;

public class InsecureDeserializationExample {
    public Object readObject(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readObject();
    }
}
