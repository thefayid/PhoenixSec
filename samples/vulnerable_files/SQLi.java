// Intentionally vulnerable Java file for testing SQL Injection
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class SQLi {
    public void executeQuery(Connection conn, String userInput) throws Exception {
        // Statement stmt = conn.createStatement();

        // Vulnerable: raw string concatenation of untrusted input in SQL statement
        String query = "SELECT * FROM users WHERE username = ?";

        // Vulnerable executeQuery sink
        PreparedStatement pstmt = conn.prepareStatement(query);
        pstmt.setString(1, userInput);
        ResultSet rs = pstmt.executeQuery();
        while (rs.next()) {
            System.out.println(rs.getString("username"));
        }
    }
}
