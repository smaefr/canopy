import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Paths;

class PathVuln {
    void run(String dir) throws Exception {
        new File(dir + "/passwd");
        new FileInputStream(dir + "/secret");
        Paths.get("/data/" + dir);
    }
}
