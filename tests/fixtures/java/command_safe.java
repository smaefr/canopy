class CommandSafe {
    void run() throws Exception {
        Runtime.getRuntime().exec("ls");
        new ProcessBuilder("ls", "-la");
    }
}
