package client;

import java.io.Serializable;
import java.security.PublicKey;

public class SecureMessage implements Serializable {
    public byte[] encryptedAESKey;
    public byte[] encryptedFile;
    public byte[] fileSignature;
    public PublicKey clientPublicKey;
    public String nonce;
    public long timestamp;
}
