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
    private static String[] file_names;
    private static String[] file_hashes;
    private static int fileCount = 0;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        String input;

        System.out.println("P2P Node started. Type 'help' for available commands.");

        while (true) {
            System.out.print("> ");
            input = scanner.nextLine().trim();
            String[] parts = input.split("\\s+", 2);
            String command = parts[0].toLowerCase();

            switch (command) {
                case "help":
                    printHelp();
                    break;
                case "submit":
                    if (parts.length > 1) {
                        submitFile(parts[1]);
                    } else {
                        System.out.println("Usage: submit <file_path>");
                    }
                    break;
                case "list":
                    System.out.println("Querying tracker for available files...");
                    listAvailableFiles();
                    break;
                case "request":
                    if (parts.length > 1) {
                        requestFile(parts[1]);
                    } else {
                        System.out.println("Usage: request <file_hash>");
                    }
                    break;
                case "exit":
                    scanner.close();
                    System.out.println("Exiting...");
                    return;
                default:
                    System.out.println("Unknown command. Type 'help' for available commands.");
            }
        }
    }

    private static void printHelp() {
        System.out.println("Available commands:");
        System.out.println("  help                - Show this help message");
        System.out.println("  submit <file_path>  - Submit a file to the tracker");
        System.out.println("  list                - List all available files");
        System.out.println("  request <file_hash> - Request a file by its hash");
        System.out.println("  exit                - Exit the application");
    }

    private static void submitFile(String filePath) {
        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            System.out.println("Error: File not found: " + filePath);
            return;
        }

        String fileName = file.getName();
        String fileHash = calculateSHA256(file);
        
        try (Socket socket = new Socket(trackerIP, communicationPort);
            OutputStreamWriter output = new OutputStreamWriter(socket.getOutputStream(), "UTF-8");
            BufferedWriter writer = new BufferedWriter(output);
            InputStream in = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"))) {
            
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
            } else {
                System.out.println("Failed to register file with tracker. Response: " + response);
            }

        } catch (IOException e) {
            System.out.println("Error communicating with tracker: " + e.getMessage());
        }
    }

    private static void listAvailableFiles() {
        try (Socket socket = new Socket(trackerIP, communicationPort);
             OutputStreamWriter output = new OutputStreamWriter(socket.getOutputStream(), "UTF-8");
             BufferedWriter writer = new BufferedWriter(output);
             InputStream in = socket.getInputStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"))) {
            
            writer.write("list");
            writer.newLine();
            writer.flush();
            
            String countStr = reader.readLine();
            if (countStr == null) {
                System.out.println("No response from tracker.");
                return;
            }
            
            int count = Integer.parseInt(countStr);
            fileCount = count;
            file_names = new String[count];
            file_hashes = new String[count];
            
            System.out.println("Available files (" + count + "):");
            for (int i = 0; i < count; i++) {
                String fileName = reader.readLine();
                String fileHash = reader.readLine();
                String peerCount = reader.readLine();
                
                file_names[i] = fileName;
                file_hashes[i] = fileHash;
                
                System.out.println((i + 1) + ". " + fileName + " (Hash: " + fileHash + ", Peers: " + peerCount + ")");
            }
            
        } catch (IOException | NumberFormatException e) {
            System.out.println("Error retrieving file list: " + e.getMessage());
        }
    }

    private static void requestFile(String fileHashOrIndex) {
        String fileHash = fileHashOrIndex;
        
        try {
            int index = Integer.parseInt(fileHashOrIndex) - 1;
            if (file_hashes != null && index >= 0 && index < fileCount) {
                fileHash = file_hashes[index];
            } else {
                System.out.println("Invalid file index. Use 'list' to see available files.");
                return;
            }
        } catch (NumberFormatException e) {
        }
        
        try (Socket socket = new Socket(trackerIP, communicationPort);
             OutputStreamWriter output = new OutputStreamWriter(socket.getOutputStream(), "UTF-8");
             BufferedWriter writer = new BufferedWriter(output);
             InputStream in = socket.getInputStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"))) {
            
            writer.write("request");
            writer.newLine();
            writer.write(fileHash);
            writer.newLine();
            writer.flush();
            
            String response = reader.readLine();
            
            if ("found".equals(response)) {
                String peerAddress = reader.readLine();
                int peerPort = Integer.parseInt(reader.readLine());
                
                System.out.println("File found. Downloading from " + peerAddress + ":" + peerPort);
                downloadFile(fileHash, peerAddress, peerPort);
            } else if ("not_found".equals(response)) {
                System.out.println("File not found on the network.");
            } else {
                System.out.println("Error: " + response);
            }
            
        } catch (IOException e) {
            System.out.println("Error requesting file: " + e.getMessage());
        }
    }
    
    private static void downloadFile(String fileHash, String peerAddress, int peerPort) {
        String fileName = null;
        
        if (file_names != null && file_hashes != null) {
            for (int i = 0; i < fileCount; i++) {
                if (fileHash.equals(file_hashes[i])) {
                    fileName = file_names[i];
                    break;
                }
            }
        }
        
        if (fileName == null) {
            fileName = "downloaded_" + fileHash.substring(0, 8) + ".file";
        }
        
        System.out.println("Downloading file: " + fileName);
        
        try (Socket socket = new Socket(peerAddress, peerPort);
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8"));
             BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"))) {
            
            // Send request for the file
            writer.write("download");
            writer.newLine();
            writer.write(fileHash);
            writer.newLine();
            writer.flush();
            
            String response = reader.readLine();
            if ("sending".equals(response)) {
                // gets file size
                long fileSize = Long.parseLong(reader.readLine());
                System.out.println("File size: " + fileSize + " bytes");
                
                // creates output file
                File outputFile = new File(fileName);
                try (FileOutputStream fileOut = new FileOutputStream(outputFile);
                     BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOut)) {
                    
                    // reads file data
                    InputStream in = socket.getInputStream();
                    byte[] buffer = new byte[8192];
                    int bytesRead;
                    long totalBytesRead = 0;
                    long lastProgressUpdate = 0;
                    
                    while (totalBytesRead < fileSize && (bytesRead = in.read(buffer, 0, (int) Math.min(buffer.length, fileSize - totalBytesRead))) != -1) {
                        bufferedOut.write(buffer, 0, bytesRead);
                        totalBytesRead += bytesRead;
                        
                        // shows progress every 10%
                        long progressPercentage = (totalBytesRead * 100) / fileSize;
                        if (progressPercentage >= lastProgressUpdate + 10) {
                            lastProgressUpdate = progressPercentage;
                            System.out.println("Download progress: " + progressPercentage + "%");
                        }
                    }
                    
                    bufferedOut.flush();
                    System.out.println("Download complete! File saved as: " + fileName);
                }
            } else {
                System.out.println("Peer refused to send file: " + response);
            }
            
        } catch (IOException e) {
            System.out.println("Error downloading file: " + e.getMessage());
        }
    }

    // add SHA256 hash calculation method
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
            System.out.println("Error calculating file hash: " + e.getMessage());
            return "";
        }
    }
}
