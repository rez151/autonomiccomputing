// This example is from _Java Examples in a Nutshell_. (http://www.oreilly.com)
// Copyright (c) 1997 by David Flanagan
// This example is provided WITHOUT ANY WARRANTY either expressed or implied.
// You may study, use, modify, and distribute it for non-commercial purposes.
// For any commercial use, see http://www.davidflanagan.com/javaexamples

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;

/**
 * This class implements a simple single-threaded proxy server.
 **/
public class SimpleProxyServer {
    private static List<String> lastLines;
    private static List<String> blacklist = new ArrayList<>();
    private static String fingerprint;

    /**
     * The main method parses arguments and passes them to runServer
     */
    public static void main(String[] args) throws IOException {
        try {
            // Check the number of arguments
            if (args.length != 3)
                throw new IllegalArgumentException("Wrong number of arguments.");
            // Get the command-line arguments: the host and port we are proxy for
            // and the local port that we listen for connections on
            String host = args[0];
            int remoteport = Integer.parseInt(args[1]);
            int localport = Integer.parseInt(args[2]);
            // Print a start-up message
            System.out.println("Starting proxy for " + host + ":" + remoteport +
                    " on port " + localport);
            // And start running the server
            runServer(host, remoteport, localport);   // never returns
        } catch (Exception e) {
            System.err.println(e);
            System.err.println("Usage: java SimpleProxyServer " +
                    "<host> <remoteport> <localport>");
        }
    }

    /**
     * This method runs a single-threaded proxy server for
     * host:remoteport on the specified local port.  It never returns.
     **/
    public static void runServer(String host, int remoteport, int localport)
            throws IOException {
        // Create a ServerSocket to listen for connections with
        ServerSocket ss = new ServerSocket(localport);

        // Start Monitoring
        monitor();

        // Create buffers for client-to-server and server-to-client communication.
        // We make one final so it can be used in an anonymous class below.
        // Note the assumptions about the volume of traffic in each direction...
        final byte[] request = new byte[1024];
        byte[] reply = new byte[4096];
        // This is a server that never returns, so enter an infinite loop.
        while (true) {
            // Variables to hold the sockets to the client and to the server.
            Socket client = null, server = null;
            try {
                // Wait for a connection on the local port
                client = ss.accept();
//Hier wird die Client-IP ausgegeben
                InetAddress localAddress = client.getLocalAddress();
                InetAddress inetAddress = client.getInetAddress();
                SocketAddress localSocketAddress = client.getLocalSocketAddress();
                SocketAddress remoteSocketAddress = client.getRemoteSocketAddress();

                System.out.println("Client-IP: " + client.getInetAddress().toString());
                // Get client streams.  Make them final so they can
                // be used in the anonymous thread below.
                final InputStream from_client = client.getInputStream();
                final OutputStream to_client = client.getOutputStream();
                // Make a connection to the real server
                // If we cannot connect to the server, send an error to the
                // client, disconnect, then continue waiting for another connection.
                try {
                    server = new Socket(host, remoteport);
                } catch (IOException e) {
                    PrintWriter out = new PrintWriter(new OutputStreamWriter(to_client));
                    out.println("Proxy server cannot connect to " + host + ":" +
                            remoteport + ":\n" + e);
                    out.flush();
                    client.close();
                    continue;
                }
                // Get server streams.
                final InputStream from_server = server.getInputStream();
                final OutputStream to_server = server.getOutputStream();
                // Make a thread to read the client's requests and pass them to the
                // server.  We have to use a separate thread because requests and
                // responses may be asynchronous.
                new Thread() {
                    public void run() {
                        int bytes_read;
                        try {
                            while ((bytes_read = from_client.read(request)) != -1) {

                                String useragent = hashString(extractUserAgent(request));

                                if (!blacklist.contains(useragent)) {
                                    to_server.write(request, 0, bytes_read);
                                    System.out.println(bytes_read + "to_server--->" + new String(request, "UTF-8") + "<---");
                                    to_server.flush();
                                }
                            }
                        } catch (IOException e) {
                        }
                        // the client closed the connection to us, so  close our
                        // connection to the server.  This will also cause the
                        // server-to-client loop in the main thread exit.
                        try {
                            to_server.close();
                        } catch (IOException e) {
                        }
                    }

                    private String extractUserAgent(byte[] request) {

                        String useragent = new String(request);
                        String lines[] = useragent.split("\r\n");

                        for(int i = 0; i < lines.length; i++){
                            if(lines[i].startsWith("User-Agent: ")){
                                useragent = lines[i].substring(12);
                            }
                        }

                        return useragent;
                    }
                }.start();
                // Meanwhile, in the main thread, read the server's responses
                // and pass them back to the client.  This will be done in
                // parallel with the client-to-server request thread above.
                int bytes_read;
                try {
                    while ((bytes_read = from_server.read(reply)) != -1) {
                        try {
                            Thread.sleep(1);
                            System.out.println(bytes_read + "to_client--->" + new String(request, "UTF-8") + "<---");
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                        to_client.write(reply, 0, bytes_read);
                        to_client.flush();
                    }
                } catch (IOException e) {
                }
                // The server closed its connection to us, so close our
                // connection to our client.  This will make the other thread exit.
                to_client.close();
            } catch (IOException e) {
                System.err.println(e);
            }
            // Close the sockets no matter what happens each time through the loop.
            finally {
                try {
                    if (server != null) server.close();
                    if (client != null) client.close();
                } catch (IOException e) {
                }
            }
        }//while(true)
    }

    public static String hashString(String toHash){
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        messageDigest.update(toHash.getBytes());
        String encryptedString = new String(messageDigest.digest());

        return encryptedString;
    }

    private static List<String> trimLines(List<String> lines) {
        for (int i = 0; i < lines.size(); i++) {
            lines.set(i, lines.get(i).split("\"")[5].trim());
        }
        return lines;
    }

    public static void monitor() {

        new Thread(() -> {
            WatchService watchService = null;
            try {
                watchService = FileSystems.getDefault().newWatchService();
                Path p = Paths.get("/var/log/apache2/");
                WatchKey watchKey = p.register(watchService, ENTRY_MODIFY);

                WatchKey key;
                while ((key = watchService.take()) != null) {
                    for (WatchEvent<?> event : key.pollEvents()) {
                        analyse();
                    }
                    key.reset();
                }
            } catch (IOException | InterruptedException e) {
                e.printStackTrace();
            }
        }).start();


    }

    public static void analyse() {

        String fileName = "/var/log/apache2/access.log";
        List<String> lines = new ArrayList<>();
        String line = null;

        try {
            FileReader fileReader = new FileReader(fileName);
            BufferedReader bufferedReader = new BufferedReader(fileReader);

            while ((line = bufferedReader.readLine()) != null) {
                lines.add(line);
            }
            bufferedReader.close();

            if (lines.size() > 2) {
                lastLines = trimLines(lines.subList(lines.size() - 3, lines.size()));

                if (lastLines.get(0).equals(lastLines.get(1)) && lastLines.get(1).equals(lastLines.get(2))) {
                    plan();
                }
            }
        } catch (FileNotFoundException ex) {
            System.out.println("Unable to open file '" + fileName + "'");
        } catch (IOException ex) {
            System.out.println("Error reading file '" + fileName + "'");
        }
    }

    public static void plan() {
        fingerprint = hashString(lastLines.get(0));
        execute();
    }

    public static void execute() {
        blacklist.add(fingerprint);
    }
}
