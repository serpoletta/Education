package cbcmac;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class DesEncrypter {
    Cipher ecipher;

    DesEncrypter(SecretKey key) throws Exception {
        ecipher = Cipher.getInstance("DES");
        ecipher.init(Cipher.ENCRYPT_MODE, key);
    }

    public byte[] encrypt(byte[] source) throws Exception {
        // Кодирование
        byte[] enc = ecipher.doFinal(source);
        return enc;
    }
}