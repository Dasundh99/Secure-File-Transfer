package crypto;

import javax.crypto.SecretKey;
import java.security.PublicKey;
import javax.crypto.Cipher;

public class RSAEncryptionUtil {

    public static byte[] encryptAESKey(SecretKey aesKey, PublicKey serverPublicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        return cipher.doFinal(aesKey.getEncoded());
    }
}
