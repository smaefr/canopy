import java.io.ObjectInputStream;

class DeserSafe {
    ObjectInputStream wrap(java.io.InputStream in) throws Exception {
        return new ObjectInputStream(in);
    }
}
