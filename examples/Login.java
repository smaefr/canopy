import java.io.File;
import java.security.MessageDigest;

class Login {
    void authenticate(java.sql.Statement stmt, String user, String extra) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + user + "'");
        Runtime.getRuntime().exec("id " + extra);
        new File("/home/" + user);
        MessageDigest.getInstance("MD5");
        String password = "s3cr3t-value";
    }
}
