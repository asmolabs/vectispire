// Fixture for the Java rules — see ../python/quality_cases.py for the marker format.
import java.security.MessageDigest;
import java.util.Random;
import javax.crypto.Cipher;
import javax.xml.parsers.DocumentBuilderFactory;

public class Cases {

    void commandExecution(String userInput) throws Exception {
        Runtime.getRuntime().exec(userInput); // zanshin: zanshin-java-runtime-exec-concatenation
        Runtime.getRuntime().exec("ls");
    }

    void database(java.sql.Statement stmt, java.sql.Connection conn, String name) throws Exception {
        stmt.executeQuery("SELECT * FROM t WHERE n = '" + name); // zanshin: zanshin-java-sql-string-concatenation
        conn.prepareStatement("SELECT * FROM t WHERE n = ?");
    }

    void cryptography() throws Exception {
        MessageDigest.getInstance("MD5"); // zanshin: zanshin-java-weak-hash
        MessageDigest.getInstance("SHA-256");
        Cipher.getInstance("DES/CBC/PKCS5Padding"); // zanshin: zanshin-java-weak-cipher
        Cipher.getInstance("AES/ECB/PKCS5Padding"); // zanshin: zanshin-java-weak-cipher
        Cipher.getInstance("AES/GCM/NoPadding");
    }

    void randomness() {
        Random sessionToken = new Random(); // zanshin: zanshin-java-insecure-random-secret
        Random jitter = new Random();
        System.out.println(sessionToken.nextInt() + jitter.nextInt()); // zanshin: zanshin-java-system-out-println
    }

    void xml() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance(); // zanshin: zanshin-java-xxe-document-builder
        factory.newDocumentBuilder();
    }

    static class AcceptEverything implements javax.net.ssl.X509TrustManager {
        public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) { } // zanshin: zanshin-java-trust-all-certificates

        public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) { } // zanshin: zanshin-java-trust-all-certificates

        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }

    void qualityCases(java.util.List<String> parts) {
        try { // zanshin: zanshin-java-empty-catch
            parts.get(0);
        } catch (RuntimeException e) {
        }
        try {
            parts.get(1);
        } catch (RuntimeException e) {
            e.printStackTrace(); // zanshin: zanshin-java-print-stack-trace
        }
        String joined = "";
        for (String part : parts) { // zanshin: zanshin-java-string-concatenation-in-loop
            joined += part;
        }
    }
}
