import java.security.MessageDigest;
import javax.crypto.Cipher;

class CryptoVuln {
    void run() throws Exception {
        MessageDigest.getInstance("MD5");
        MessageDigest.getInstance("SHA-1");
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher.getInstance("DES");
    }
}
