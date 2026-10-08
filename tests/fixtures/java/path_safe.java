import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Paths;

class PathSafe {
    void run() throws Exception {
        new File("/tmp/fixed");
        new FileInputStream("/tmp/fixed");
        Paths.get("/tmp", "fixed");
    }
}
