// ME
import java.io.*;
import java.net.*;
import java.util.*;
import FileHashUtil.calculateSHA256;

public class Node {
    private static final String trackerIP = "127.0.0.1";
    private static final int communicationPort = 54321;
    private String[] file_names;
    private String[] file_hashes;

    public static void main(String[] args) {
        // enter interactive mode where execute commands
        Scanner scanner = new Scanner(System.in);
        String input;

        while (true) {
            System.out.print("> ");
            input = scanner.nextLine().trim();

            switch (input.toLowerCase()) {
                case "help":
                    // print available commands
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
        // tell server we wanna put up a file at this path for downloading

        File file = new File(filePath);
        String fileName = file.getName();
        String fileHash = calculateSHA256(file);
        try (Socket socket = new Socket(trackerIP, communicationPort);
            socket.setSoTimeout(15000);
            OutputStreamWriter output = new OutputStreamWriter(socket.getOutputStream(), "UTF-8");
            BufferedWriter writer = new BufferedWriter(output)
            InputStream in = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, "UTF-8"))) {
            
            // Send file name and file hash
            writer.write("submit");
            writer.newLine();
            writer.write(fileName);
            writer.write(fileHash);
            writer.flush();

            String response = reader.readLine();
            if (response == "received") {
                System.out.println("Successfully sent file " + fileName + " with hash " + fileHash + ".")
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
}
