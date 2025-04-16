import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;

public class Tracker {
    private static final int PORT = 54321;
    private final Map<String, Set<NodeInfo>> fileRegistry = new ConcurrentHashMap<>();
    private final Map<String, String> fileNames = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        new Tracker().start();
    }

    private void start() {
        System.out.println("Tracker starting on port " + PORT);
        
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            while (true) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    new Thread(() -> handleClient(clientSocket)).start();
                } catch (IOException e) {
                    System.err.println("Error accepting connection: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("Could not start tracker: " + e.getMessage());
        }
    }

    private void handleClient(Socket clientSocket) {
        try {
            clientSocket.setSoTimeout(30000); 
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(clientSocket.getInputStream(), "UTF-8"));
            BufferedWriter writer = new BufferedWriter(
                    new OutputStreamWriter(clientSocket.getOutputStream(), "UTF-8"));

            String command = reader.readLine();
            if (command == null) {
                return;
            }

            switch (command.toLowerCase()) {
                case "submit":
                    handleSubmit(reader, writer, clientSocket);
                    break;
                case "list":
                    handleList(writer);
                    break;
                case "request":
                    handleRequest(reader, writer);
                    break;
                default:
                    writer.write("unknown_command");
                    writer.newLine();
                    writer.flush();
            }
        } catch (IOException e) {
            System.err.println("Error handling client: " + e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                System.err.println("Error closing client socket: " + e.getMessage());
            }
        }
    }

    private void handleSubmit(BufferedReader reader, BufferedWriter writer, Socket clientSocket) throws IOException {
        String fileName = reader.readLine();
        String fileHash = reader.readLine();
        
        if (fileName == null || fileHash == null) {
            writer.write("error");
            writer.newLine();
            writer.flush();
            return;
        }

        String clientAddress = clientSocket.getInetAddress().getHostAddress();
        int clientPort = clientSocket.getPort();
        
        NodeInfo nodeInfo = new NodeInfo(clientAddress, clientPort);
        
        fileRegistry.computeIfAbsent(fileHash, k -> ConcurrentHashMap.newKeySet()).add(nodeInfo);
        fileNames.put(fileHash, fileName);
        
        System.out.println("Registered file: " + fileName + " with hash " + fileHash + " from " + clientAddress);
        
        writer.write("received");
        writer.newLine();
        writer.flush();
    }

    private void handleList(BufferedWriter writer) throws IOException {
        writer.write(Integer.toString(fileNames.size()));
        writer.newLine();
        
        for (Map.Entry<String, String> entry : fileNames.entrySet()) {
            writer.write(entry.getValue()); // File name
            writer.newLine();
            writer.write(entry.getKey());   // File hash
            writer.newLine();
            writer.write(Integer.toString(fileRegistry.get(entry.getKey()).size())); // Number of peers
            writer.newLine();
        }
        
        writer.flush();
    }

    private void handleRequest(BufferedReader reader, BufferedWriter writer) throws IOException {
        String fileHash = reader.readLine();
        
        if (fileHash == null) {
            writer.write("error");
            writer.newLine();
            writer.flush();
            return;
        }
        
        Set<NodeInfo> nodes = fileRegistry.get(fileHash);
        
        if (nodes == null || nodes.isEmpty()) {
            writer.write("not_found");
            writer.newLine();
            writer.flush();
            return;
        }
        
        NodeInfo selectedNode = nodes.iterator().next();
        
        writer.write("found");
        writer.newLine();
        writer.write(selectedNode.getAddress());
        writer.newLine();
        writer.write(Integer.toString(selectedNode.getPort()));
        writer.newLine();
        writer.flush();
    }

    private static class NodeInfo {
        private final String address;
        private final int port;
        
        public NodeInfo(String address, int port) {
            this.address = address;
            this.port = port;
        }
        
        public String getAddress() {
            return address;
        }
        
        public int getPort() {
            return port;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            NodeInfo nodeInfo = (NodeInfo) o;
            return port == nodeInfo.port && Objects.equals(address, nodeInfo.address);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(address, port);
        }
    }
}
