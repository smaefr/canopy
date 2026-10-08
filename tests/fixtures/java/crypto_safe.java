import java.security.MessageDigest;
import javax.crypto.Cipher;

class CryptoSafe {
    void run() throws Exception {
        MessageDigest.getInstance("SHA-256");
        Cipher.getInstance("AES/GCM/NoPadding");
    }
}
