class CommandVuln {
    void run(String name) throws Exception {
        Runtime.getRuntime().exec("ls " + name);
        new ProcessBuilder("sh", "-c", "echo " + name);
    }
}
