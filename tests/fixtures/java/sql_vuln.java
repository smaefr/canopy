class SqlVuln {
    void run(java.sql.Statement stmt, String name) {
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        stmt.execute(String.format("DELETE FROM users WHERE name = %s", name));
        stmt.executeUpdate("UPDATE users SET name = ".concat(name));
    }
}
