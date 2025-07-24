package client;

import crypto.*;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.file.*;
import java.security.*;

public class Client {

    public static void main(String[] args) throws Exception {
        // 1. Generate AES key
        SecretKey aesKey = AESUtil.generateAESKey();

        // 2. Load or create client RSA key pair (FIX)
        KeyPair clientKeys;
        File keyFile = new File("client.key");
        if (keyFile.exists()) {
            clientKeys = RSAKeyUtil.loadKeyPair("client.key");
            System.out.println("Loaded existing client key pair");
        } else {
            clientKeys = RSAKeyUtil.generateRSAKeyPair();
            RSAKeyUtil.saveKeyPair("client.key", clientKeys);
            System.out.println("Generated and saved new client key pair");
        }

        // 3. Read file bytes
        byte[] fileData = Files.readAllBytes(Path.of("test.txt"));

        // 4. Encrypt file using AES key
        byte[] encryptedFile = AESUtil.encryptFile(fileData, aesKey);

        // 5. Connect to server and get server's RSA public key
        Socket socket = new Socket("localhost", 5000);
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        PublicKey serverPublicKey = (PublicKey) in.readObject();

        // 6. Encrypt AES key with server's RSA public key
        byte[] encryptedAESKey = RSAEncryptionUtil.encryptAESKey(aesKey, serverPublicKey);

        // 7. Sign file data using client private key
        byte[] fileSignature = SignatureUtil.signData(fileData, clientKeys.getPrivate());

        // 8. Generate nonce and timestamp
        SecureRandom random = new SecureRandom();
        String nonce = Long.toHexString(random.nextLong());
        long timestamp = System.currentTimeMillis();

        // 9. Create message object and populate
        SecureMessage message = new SecureMessage();
        message.encryptedAESKey = encryptedAESKey;
        message.encryptedFile = encryptedFile;
        message.fileSignature = fileSignature;
        message.clientPublicKey = clientKeys.getPublic();
        message.nonce = nonce;
        message.timestamp = timestamp;

        // 10. Send message
        out.writeObject(message);
        out.flush();

        System.out.println("File sent securely with nonce + timestamp");

        // 11. Close connection
        socket.close();
    }
}
