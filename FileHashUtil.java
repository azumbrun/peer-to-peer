import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class FileHashUtil {

    /**
     * Computes the SHA-256 hash of the given file.
     *
     * @param file The file to hash.
     * @return A hexadecimal string representation of the file's SHA-256 hash.
     * @throws IOException If an I/O error occurs reading from the file.
     * @throws NoSuchAlgorithmException If SHA-256 is not supported.
     */
    public static String calculateSHA256(File file) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }
        byte[] hashBytes = digest.digest();
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}

