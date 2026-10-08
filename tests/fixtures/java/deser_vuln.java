import java.io.ObjectInputStream;

class DeserVuln {
    Object run(ObjectInputStream in) throws Exception {
        return in.readObject();
    }
}
