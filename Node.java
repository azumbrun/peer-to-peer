import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.file.Files;

public class Node {
    private static final String trackerIP = "127.0.0.1";
    private static final int trackerPort = 54321;
    private static int nodePort = 54322;
    private static ConcurrentHashMap<String, String> fileNames = new ConcurrentHashMap<>();
    private static ConcurrentHashMap<String, String> fileHashes = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        System.out.println("Chosen port: " + args[0]);

        nodePort = Integer.parseInt(args[0]);

        Scanner scanner = new Scanner(System.in);
        String input;

        Thread senderThread = new Thread(new FileSender());
        senderThread.start();
        System.out.println("P2P Node started. Type 'help' for available commands.");

        while (true) {
            System.out.print("> ");
            input = scanner.nextLine().trim();
            args = input.trim().split("\\s+");

            switch (args[0].toLowerCase()) {
                case "help":
                    printHelp();
                    break;
                case "submit":
                    if (args.length < 2) {
                        System.out.println("Error: 'submit' requires 2 arguments");
                        break;
                    }
                    submitFile(args[1]);
                    break;
                case "list":
                    System.out.println("Querying tracker for available files...");
                    listAvailableFiles();
                    break;
                case "request":
                    requestFile(args[1]);
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

    private static class FileSender implements Runnable {
        @Override
        public void run() {
            try (ServerSocket serverSocket = new ServerSocket(nodePort)) {
                System.out.println("Listening for file requests...");

                Socket socket = serverSocket.accept();
                System.out.println("File request received");

                // First read requested file name
                BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String requestedFileHash = reader.readLine();
                System.out.println("Client requested file " + requestedFileHash);

                File file = new File(fileHashes.get(requestedFileHash));
                if (!file.exists()) {
                    System.out.println("Requested file does not exist.");
                    socket.close();
                    return;
                }

                // Then send file contents
                BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file));
                OutputStream out = socket.getOutputStream();
                byte[] buffer = new byte[4096];
                int count;
                while ((count = bis.read(buffer)) > 0) {
                    out.write(buffer, 0, count);
                }

                bis.close();
                socket.close();
                System.out.println("File sent.");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static void registerFile(String fileName, String fileHash) {
        fileNames.put(fileName, fileHash);
        fileHashes.put(fileHash, fileName);
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
        try (Socket socket = new Socket(trackerIP, trackerPort);
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
                registerFile(fileName, fileHash);
            } else {
                System.out.println("Failed to register file with tracker. Response: " + response);
            }

        } catch (IOException e) {
            System.out.println("Error communicating with tracker: " + e.getMessage());
        }
    }

    private static void listAvailableFiles() {
        // query server for files; update file list and print
        try (Socket socket = new Socket(trackerIP, trackerPort);
            OutputStreamWriter output = new OutputStreamWriter(socket.getOutputStream(), "UTF-8");
            BufferedWriter writer = new BufferedWriter(output);
            InputStream in = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"))) {
            
            // Send command
            writer.write("list");
            writer.newLine();
            writer.flush();

            // parse response
            System.out.println("File Name\t\tFile Hash\t\tNumber of Peers");
            String line;
            
            // clear hashmaps
            fileNames.clear();
            fileHashes.clear();

            while ((line = reader.readLine()) != null) {
                int numPeers = Integer.parseInt(line);
                String fileName = reader.readLine();
                String fileHash = reader.readLine();

                if (numPeers < 1 || fileName == null || fileHash == null) {
                    // ignore this file since it can't be downloaded
                    continue;
                }

                System.out.println(fileName + "\t\t" + fileHash.substring(0,7) + "\t\t\t" + numPeers);
                registerFile(fileName, fileHash);
            }
            
            System.out.println("Successfully listed files");

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void requestFile(String fileName) {
        // ask tracker for this file.
        // tracker returns the ip of a node who has it and is willing to send it.
        // so we connect to that guy (as a client? could also connect as a server
        // but should be six of one half dozen of the other) and start downloading.

        String fileHash = fileNames.get(fileName); 

        String senderIP = "";
        int senderPort = 0;

        // query server for files; update file list and print
        try (Socket socket = new Socket(trackerIP, trackerPort);
            OutputStreamWriter output = new OutputStreamWriter(socket.getOutputStream(), "UTF-8");
            BufferedWriter writer = new BufferedWriter(output);
            InputStream in = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"))) {
            
            // Send command
            writer.write("request");
            writer.newLine();
            writer.write(fileHash);
            writer.newLine();
            writer.flush();
            String response = reader.readLine();
            
            // parse response
            if ("not_found".equals(response)) {
                System.out.println("Failed to request file. Please try again.");
            } else {
                senderIP = reader.readLine();
                senderPort = Integer.parseInt(reader.readLine());
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        // download the file
        try (Socket socket = new Socket(senderIP, senderPort);
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
            InputStream in = socket.getInputStream();
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream("received_" + fileHashes.get(fileHash)))) {
            
            writer.write(fileHash);
            writer.newLine();
            writer.flush();
            
            byte[] buffer = new byte[4096];
            int count;
            while ((count = in.read(buffer)) > 0) {
                bos.write(buffer, 0, count);
            }

            bos.close();
            socket.close();
            System.out.println("File received.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    private static void sendFile(String fileName) {
        String fileHash = "";

        String senderIP;
        String senderPort;

        // query server for files; update file list and print
        try (Socket socket = new Socket(trackerIP, trackerPort);
            OutputStreamWriter output = new OutputStreamWriter(socket.getOutputStream(), "UTF-8");
            BufferedWriter writer = new BufferedWriter(output);
            InputStream in = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"))) {
            
            // Send command
            writer.write("request");
            writer.newLine();
            writer.write(fileHash);
            writer.newLine();
            writer.flush();
            String response = reader.readLine();
            
            // parse response
            if ("not_found".equals(response)) {
                System.out.println("Failed to request file. Please try again.");
            } else {
                senderIP = reader.readLine();
                senderPort = reader.readLine();
            }

        } catch (IOException e) {
            e.printStackTrace();
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
