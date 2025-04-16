// ME
import java.io.*;
import java.net.*;
import java.util.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.file.Files;

public class Node {
    private static final String trackerIP = "127.0.0.1";
    private static final int communicationPort = 54321;
    private String[] file_names;
    private String[] file_hashes;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        String input;

        while (true) {
            System.out.print("> ");
            input = scanner.nextLine().trim();

            switch (input.toLowerCase()) {
                case "help":
                    break;
                case "submit":
                    submitFile("foo");
                    break;
                case "list":
                    System.out.println("Querying tracker for available files...");
                    listAvailableFiles();
                    break;
                case "request":
                    requestFile("foo");
                    break;
                case "exit":
                    scanner.close();
                    return;
                default:
                    System.out.println("Unknown command.");
            }
        }
    }

    private static void submitFile(String filePath) {
        File file = new File(filePath);
        String fileName = file.getName();
        String fileHash = calculateSHA256(file);
        try (Socket socket = new Socket(trackerIP, communicationPort);
            OutputStreamWriter output = new OutputStreamWriter(socket.getOutputStream(), "UTF-8");
            BufferedWriter writer = new BufferedWriter(output);
            InputStream in = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"))) {
            
            // Send file name and file hash
            writer.write("submit");
            writer.newLine();
            writer.write(fileName);
            writer.newLine();
            writer.write(fileHash);
            writer.newLine();
            writer.flush();

            String response = reader.readLine();
            if ("received".equals(response)) {
                System.out.println("Successfully sent file " + fileName + " with hash " + fileHash + ".");
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void listAvailableFiles() {
        // query server for files; update file list and print
    }

    private static void requestFile(String fileHash) {
        // ask tracker for this file.
        // tracker returns the ip of a node who has it and is willing to send it.
        // so we connect to that guy (as a client? could also connect as a server
        // but should be six of one half dozen of the other) and start downloading.
    }

    // Add SHA256 hash calculation method
    private static String calculateSHA256(File file) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] fileBytes = Files.readAllBytes(file.toPath());
            byte[] hashBytes = digest.digest(fileBytes);
            
            StringBuilder hexString = new StringBuilder();
            for (byte hashByte : hashBytes) {
                String hex = Integer.toHexString(0xff & hashByte);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            return "";
        }
    }
}
