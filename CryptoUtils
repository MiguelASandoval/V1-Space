import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Base64;
import java.awt.Desktop;

public class CryptoUtils {
    public static byte[] encryptFile(File inputFile, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    outputStream.write(output);
                }
            }
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                outputStream.write(outputBytes);
            }
            return outputStream.toByteArray();
        }
    }

    public static File decryptToFile(File encryptedFile, SecretKey secretKey, String tempFileName) throws Exception {
        byte[] decryptedData = decryptFile(encryptedFile, secretKey);
        File tempFile = new File(tempFileName);
        try (FileOutputStream fos = new FileOutputStream(tempFile)) {
            fos.write(decryptedData);
        }
        return tempFile;
    }

    public static byte[] decryptFile(File inputFile, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    outputStream.write(output);
                }
            }
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                outputStream.write(outputBytes);
            }
            return outputStream.toByteArray();
        }
        
    }
    

    public static SecretKey loadKeyFromFile(String filePath) throws Exception {
        // Read the file content (Base64 encoded key)
        byte[] base64Key = Files.readAllBytes(Paths.get(filePath));
        // Decode the Base64 encoded key
        byte[] decodedKey = Base64.getDecoder().decode(new String(base64Key).trim());
        // Rebuild key using SecretKeySpec
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public static boolean verifyReportIntegrity(File encryptedFile, File hashFile) throws Exception {
        byte[] encryptedData = Files.readAllBytes(encryptedFile.toPath());
        String currentHash = computeHash(encryptedData);
        String savedHash = new String(Files.readAllBytes(hashFile.toPath()), "UTF-8");

        return currentHash.equals(savedHash);
    }
    public class FileOpener {
        public static void openFile(File file) throws IOException {
            if (Desktop.isDesktopSupported()) {
                Desktop desktop = Desktop.getDesktop();
                if (file.exists()) {
                    desktop.open(file);
                }
            } else {
                throw new UnsupportedOperationException("Desktop is not supported, cannot open files automatically.");
            }
        }
    }

    public static String computeHash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        return Base64.getEncoder().encodeToString(hash);
    }

    public static void writeToFile(File outputFile, byte[] data) throws IOException {
        try (FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            outputStream.write(data);
        }
    }

    public static SecretKey generateKey() throws Exception {
        return KeyGenerator.getInstance("AES").generateKey();
    }
}
