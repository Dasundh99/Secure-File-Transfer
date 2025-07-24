package server;

import client.SecureMessage;
import crypto.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.*;

public class Server {

    private static final Set<String> usedNonces = new HashSet<>();

    public static void main(String[] args) throws Exception {
        // Generate RSA key pair for server (public/private)
        KeyPair serverKeyPair = RSAKeyUtil.generateRSAKeyPair();
        ServerSocket serverSocket = new ServerSocket(5000);

        System.out.println("Server started on port 5000...");

        while (true) {
            Socket clientSocket = serverSocket.accept();
            System.out.println("\nClient connected");

            ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());

            // Send server's public key
            out.writeObject(serverKeyPair.getPublic());
            out.flush();

            // Read secure message from client
            SecureMessage msg = (SecureMessage) in.readObject();

            // Decrypt AES key using server private key
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.DECRYPT_MODE, serverKeyPair.getPrivate());
            byte[] aesKeyBytes = rsaCipher.doFinal(msg.encryptedAESKey);
            SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

            // Decrypt the encrypted file using the AES key
            Cipher aesCipher = Cipher.getInstance("AES");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] fileData = aesCipher.doFinal(msg.encryptedFile);

            // Replay attack protection using nonce
            if (usedNonces.contains(msg.nonce)) {
                System.out.println("Replay attack detected! Nonce already used: " + msg.nonce);
                clientSocket.close();
                continue;
            }
            usedNonces.add(msg.nonce);

            // Timestamp validation (within 5-minute window)
            long now = System.currentTimeMillis();
            if (Math.abs(now - msg.timestamp) > 5 * 60 * 1000) {
                System.out.println("Timestamp is too old or too far ahead: " + msg.timestamp);
                clientSocket.close();
                continue;
            }

            // Signature verification using client's provided public key
            boolean valid = SignatureUtil.verifySignature(fileData, msg.fileSignature, msg.clientPublicKey);

            if (valid) {
                System.out.println("File received and signature verified.");
                Files.write(Path.of("received_file.txt"), fileData);
                System.out.println("File written to 'received_file.txt'");
            } else {
                System.out.println("Invalid signature. File rejected.");
            }

            clientSocket.close();
        }
    }
}
