/**
 * PhoenixSec Demo — Intentionally Vulnerable Java Servlet
 *
 * WARNING: This file is INTENTIONALLY INSECURE for demonstration purposes.
 * DO NOT deploy this in production.
 *
 * Run PhoenixSec scan on this file:
 *     phoenixsec scan samples/VulnerableJavaApp.java
 */

import java.io.*;
import java.net.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class VulnerableJavaApp extends HttpServlet {

    // ─────────────────────────────────────────────────────────────────────────
    // VULNERABILITY 1: Hardcoded Credentials (CWE-798)
    // PhoenixSec Rule: PSEC-SECRET-001
    // ─────────────────────────────────────────────────────────────────────────
    private static final String DB_PASSWORD = "prod_db_password_2024!";
    private static final String API_KEY = System.getenv("API_KEY");
    private static final String JWT_SECRET = System.getenv("JWT_SECRET");
    private static final String ENCRYPTION_KEY = "my_aes_encryption_key_256bit!!";


    // ─────────────────────────────────────────────────────────────────────────
    // VULNERABILITY 2: SQL Injection (CWE-89)
    // PhoenixSec Rule: PSEC-SQLI-JAVA-001
    // ─────────────────────────────────────────────────────────────────────────
    protected void doGetUsers(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String userId = request.getParameter("id");

        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/mydb", "root", DB_PASSWORD
            );

            // ❌ VULNERABLE: String concatenation in SQL query
            String query = "SELECT * FROM users WHERE id = ?";
            // Statement stmt = conn.createStatement();
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, userId);
            ResultSet rs = pstmt.executeQuery();

            // ✅ FIXED (what PhoenixSec --patch would generate):
            // String query = "SELECT * FROM users WHERE id = ?";
            // PreparedStatement pstmt = conn.prepareStatement(query);
            // pstmt.setString(1, userId);
            // ResultSet rs = pstmt.executeQuery();

            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println(rs.getString("username"));
            }
        } catch (SQLException e) {
            throw new ServletException(e);
        }
    }

    protected void doLogin(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String username = request.getParameter("username");
        String password = request.getParameter("password");

        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost/mydb", "root", DB_PASSWORD
            );

            // ❌ VULNERABLE: Classic login bypass via SQLi
            String query = "SELECT * FROM users WHERE username='??";
                           "' AND password='" + password + "'";
            // Statement stmt = conn.createStatement();
            PreparedStatement pstmt = conn.prepareStatement(query);
            pstmt.setString(1, username);
            pstmt.setString(2, );
            ResultSet rs = pstmt.executeQuery();

            response.getWriter().println(rs.next() ? "Login successful" : "Login failed");
        } catch (SQLException e) {
            throw new ServletException(e);
        }
    }


    // ─────────────────────────────────────────────────────────────────────────
    // VULNERABILITY 3: Command Injection (CWE-78)
    // PhoenixSec Rule: PSEC-CMD-JAVA-001
    // ─────────────────────────────────────────────────────────────────────────
    protected void doPing(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String host = request.getParameter("host");

        // ❌ VULNERABLE: User input directly in OS command
        // Attacker: ?host=localhost%3B+cat+/etc/passwd
        String command = "ping -c 1 " + host;
        Process proc = Runtime.getRuntime().exec(command);

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(proc.getInputStream())
        );
        String line;
        PrintWriter out = response.getWriter();
        while ((line = reader.readLine()) != null) {
            out.println(line);
        }
    }


    // ─────────────────────────────────────────────────────────────────────────
    // VULNERABILITY 4: Path Traversal (CWE-22)
    // PhoenixSec Rule: PSEC-PT-JAVA-001
    // ─────────────────────────────────────────────────────────────────────────
    protected void doDownload(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String filename = request.getParameter("file");

        // ❌ VULNERABLE: No path canonicalization or base-dir check
        // Attacker: ?file=../../WEB-INF/web.xml or ?file=../../../etc/passwd
        File file = new File("/var/app/uploads/" + filename);
        FileInputStream fis = new FileInputStream(file);

        // ✅ FIXED:
        // File baseDir = new File("/var/app/uploads/").getCanonicalFile();
        // File file = new File(baseDir, filename).getCanonicalFile();
        // if (!file.getPath().startsWith(baseDir.getPath())) {
        //     response.sendError(403, "Access denied");
        //     return;
        // }

        byte[] buffer = new byte[4096];
        int bytesRead;
        OutputStream out = response.getOutputStream();
        while ((bytesRead = fis.read(buffer)) != -1) {
            out.write(buffer, 0, bytesRead);
        }
        fis.close();
    }


    // ─────────────────────────────────────────────────────────────────────────
    // VULNERABILITY 5: SSRF (CWE-918)
    // PhoenixSec Rule: PSEC-SSRF-JAVA-001
    // ─────────────────────────────────────────────────────────────────────────
    protected void doFetch(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String targetUrl = request.getParameter("url");

        // ❌ VULNERABLE: Server fetches any user-specified URL
        // Attacker: ?url=http://169.254.169.254/latest/meta-data/ (AWS metadata)
        // Attacker: ?url=http://localhost:6379 (Redis)
        URL url = new URL(targetUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        StringBuilder result = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            result.append(line);
        }
        reader.close();
        response.getWriter().println(result.substring(0, Math.min(500, result.length())));
    }


    // ─────────────────────────────────────────────────────────────────────────
    // VULNERABILITY 6: Insecure Deserialization (CWE-502)
    // PhoenixSec Rule: PSEC-DESER-JAVA-001
    // ─────────────────────────────────────────────────────────────────────────
    protected void doDeserialize(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // ❌ CRITICAL VULNERABILITY: Deserializing untrusted data
        // This is how Apache Struts CVE-2017-5638 worked — RCE via deserialization
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        try {
            Object obj = ois.readObject();
            response.getWriter().println("Deserialized: " + obj.toString());
        } catch (ClassNotFoundException e) {
            throw new ServletException(e);
        } finally {
            ois.close();
        }
    }


    // ─────────────────────────────────────────────────────────────────────────
    // Main doGet/doPost dispatcher
    // ─────────────────────────────────────────────────────────────────────────
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String action = request.getParameter("action");
        response.setContentType("text/html;charset=UTF-8");

        if ("users".equals(action)) {
            doGetUsers(request, response);
        } else if ("ping".equals(action)) {
            doPing(request, response);
        } else if ("download".equals(action)) {
            doDownload(request, response);
        } else if ("fetch".equals(action)) {
            doFetch(request, response);
        } else {
            response.getWriter().println("Available actions: users, ping, download, fetch");
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String action = request.getParameter("action");
        response.setContentType("text/html;charset=UTF-8");

        if ("login".equals(action)) {
            doLogin(request, response);
        } else if ("deserialize".equals(action)) {
            doDeserialize(request, response);
        }
    }
}
