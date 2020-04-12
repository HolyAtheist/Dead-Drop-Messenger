package deaddrop_prototype;


import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class CryptUtils {

    protected static byte[] generateSecureIV() {
        SecureRandom secureRandom = null;
        try {
            secureRandom = SecureRandom.getInstance("DEFAULT", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        byte[] generatedIV = new byte[16];
        assert secureRandom != null;
        secureRandom.nextBytes(generatedIV);
        return generatedIV;
    }

    protected static SecretKey getPBKDHashKey(char[] chars, byte[] salt) {
        //simple method for hashing name and password
        //using Password-Based Key Derivation Function 2
        //basically as written on the slides

        var iterations = 5000; //hardcoded for now, could be settings
        var keyLen = 128;

        try {
            PBEKeySpec keySpec = new PBEKeySpec(chars, salt, iterations, keyLen);
// specifying data for key derivation
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA256", "BC");
// specifying algorithm for key derivation
            SecretKey key = factory.generateSecret(keySpec);
// the actual key derivation with iterated hashing
// key may now be passed to Cipher.init() (which accepts instances of interface SecretKey)
            if (key != null) {
                return key;
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    }


