class SqlSafe {
    void run(java.sql.Statement stmt, String name, String query) {
        stmt.executeQuery("SELECT 1");
        stmt.executeQuery(query);
        stmt.executeUpdate(name);
    }
}
