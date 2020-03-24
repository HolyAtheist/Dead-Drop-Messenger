package sample;

import javafx.collections.ObservableList;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Objects;

public class IOLocalController {
    private static Model model;

    public IOLocalController(Model model) {
        this.model = model;
    }

    static String retrieveMessage()  {

        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();
        byte[] passSalt = model.getNameSalt();
        byte[] nameSalt = model.getPassSalt();

        SecretKey passSecretKey = null;

        byte[] decryptedBytes = new byte[0];

        String stringNameHashCalculated = Hex.toHexString(Base64.toBase64String(Objects.requireNonNull(getPBKDHashKey(nameBytes, nameSalt)).getEncoded()).getBytes());
        byte[] readIV = Base64.decode(FileUtils.readAllBytes(stringNameHashCalculated + ".iv"));
        byte[] readEncryptedMessage = Base64.decode(FileUtils.readAllBytes(stringNameHashCalculated + ".aes"));

        //get Secretkey
        passSecretKey = Objects.requireNonNull(getPBKDHashKey(passBytes, passSalt));

        //input iv
        IvParameterSpec ivParams = new IvParameterSpec(readIV);

        //do decryption
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, passSecretKey, ivParams );
            decryptedBytes = cipher.doFinal(readEncryptedMessage);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | NoSuchProviderException e) {
            e.printStackTrace();
        }

/*        try {
// reading medical record + stored hash
            String stringNameHashCalculated = Hex.toHexString(Base64.toBase64String(Objects.requireNonNull(getPBKDHashKey(nameBytes, nameSalt)).getEncoded()).getBytes());

            System.out.println("Verifying hash of stored message..");
            inputBytes = FileUtils.readAllBytes(stringNameHashCalculated + ".txt");
            byte[] storedHashValue =
                    FileUtils.readAllBytes(stringNameHashCalculated + ".sha256");
// computing new hash
            MessageDigest mDigest = null;
            try {
                mDigest = MessageDigest.getInstance("SHA-256", "BC");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            }
            mDigest.update(inputBytes);
            byte[] computedHashValue = mDigest.digest();

// verifying
            if (MessageDigest
                    .isEqual(storedHashValue,
                            computedHashValue)) {
                System.out.println("Hash values are equal");
                System.out.println("Hash stored value: " + Hex.toHexString(storedHashValue));
                System.out.println("Hash calculated value: " + Hex.toHexString(computedHashValue));
            } else {
                System.out.println("Hash values are not equal");
                System.out.println("Hash stored value: " + Hex.toHexString(storedHashValue));
                System.out.println("Hash calculated value: " + Hex.toHexString(computedHashValue));
            }
        } catch (Exception e) {
        }*/

        String txt = new String(decryptedBytes);
        //System.out.println("built str txt: " + txt);
        return txt;

    }

    static void storeMessage(ObservableList<CharSequence> paragraph) {
        //need to join charsequence list with newlines in between
        byte[] textArea = String.join("\n", paragraph).getBytes();

        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();
        byte[] passSalt = model.getNameSalt();
        byte[] nameSalt = model.getPassSalt();

        SecretKey passSecretKey = null;
        byte[] encryptedMessage = null;

       /*         // hashing message w sha
        MessageDigest mDigest = null;
        try {
            mDigest = MessageDigest.getInstance("SHA-256", "BC");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        mDigest.update(textArea);
        byte[] hashValue = mDigest.digest();*/


        ////encrypt mess

        //get random iv
        SecureRandom secureRandom = null;
        try {
            secureRandom = SecureRandom.getInstance("DEFAULT", "BC");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        byte[] generatedIV = new byte[16];
        secureRandom.nextBytes(generatedIV);
        IvParameterSpec ivParams = new IvParameterSpec(generatedIV);

        //get Secretkey
        passSecretKey = Objects.requireNonNull(getPBKDHashKey(passBytes, passSalt));

        //do encryption
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, passSecretKey, ivParams);
            encryptedMessage = cipher.doFinal(textArea);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        //write files
        String stringNameHashCalculated = Hex.toHexString(Base64.toBase64String(Objects.requireNonNull(getPBKDHashKey(nameBytes, nameSalt)).getEncoded()).getBytes());
        byte[] iv = Base64.toBase64String(generatedIV).getBytes();

      //  String outFile = stringNameHashCalculated + "." + "sha256";
      //  FileUtils.write(outFile, hashValue);
        //System.out.println("Hashvalue: " + Hex.toHexString(hashValue));
        String ivOutFile = stringNameHashCalculated + "." + "iv";
        FileUtils.write(ivOutFile, iv);

        String outTextArea = stringNameHashCalculated + "." + "aes";
        FileUtils.write(outTextArea,  Base64.toBase64String(Objects.requireNonNull(encryptedMessage)).getBytes());

    }

    static boolean retrieveAccount() {

        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();

        String stringNameHashCalculated = null;
        String stringPassHashCalculated = null;

        String stringNameHashRetrieved = null;
        String stringPassHashRetrieved = null;
        String stringPassSaltRetrieved = null;
        String stringNameSaltRetrieved = null;
        byte[] passSaltRetrieved = null;
        byte[] nameSaltRetrieved = null;

        boolean check = false;

        String currentDirectory = System.getProperty("user.dir");
        String[] files;
        files = FileUtils.getAllFileNames(currentDirectory, "acc");
        System.out.println(Arrays.toString(files));

        for (String filename : files
        ) {
            String name = filename.substring(0, filename.lastIndexOf('.'));
            stringNameHashRetrieved = name;
            byte[] fileBytes = FileUtils.readAllBytes(name + ".acc");
            String fileString = new String(fileBytes);
            System.out.println(fileString);
            String[] fileContents = fileString.split(",");
            stringPassSaltRetrieved = fileContents[0];
            stringNameSaltRetrieved = fileContents[1];
            stringPassHashRetrieved = fileContents[2];

            passSaltRetrieved = Hex.decode(stringPassSaltRetrieved);
            nameSaltRetrieved = Hex.decode(stringNameSaltRetrieved);

            // System.out.println(stringPassSaltRetrieved);
            //  System.out.println(stringNameSaltRetrieved);
            //  System.out.println(stringPassHashRetrieved);

            stringNameHashCalculated = Base64.toBase64String(Objects.requireNonNull(getPBKDHashKey(nameBytes, nameSaltRetrieved)).getEncoded());
            stringPassHashCalculated = Base64.toBase64String(Objects.requireNonNull(getPBKDHashKey(passBytes, passSaltRetrieved)).getEncoded());

          //  stringNameHashCalculated = Hex.toHexString(Objects.requireNonNull(getPBKDHashKey(nameBytes, nameSaltRetrieved)).getEncoded());
           // stringPassHashCalculated = Hex.toHexString(Objects.requireNonNull(getPBKDHashKey(passBytes, passSaltRetrieved)).getEncoded());

            System.out.println("name hash ret  " + stringNameHashRetrieved);
            System.out.println("name hash calc " + Hex.toHexString(stringNameHashCalculated.getBytes()));

            System.out.println("pass hash ret  " + stringPassHashRetrieved);
            System.out.println("pass hash calc " + Hex.toHexString(stringPassHashCalculated.getBytes()));

            if (MessageDigest
                    .isEqual(Hex.toHexString(stringNameHashCalculated.getBytes()).getBytes(),
                            stringNameHashRetrieved.getBytes()) &&
                    MessageDigest
                            .isEqual(Hex.toHexString(stringPassHashCalculated.getBytes()).getBytes(),
                                    stringPassHashRetrieved.getBytes())) {

                model.setNameSalt(nameSaltRetrieved);
                model.setPassSalt(passSaltRetrieved);
                System.out.println("nam hash equal");
                System.out.println("pass hash equal");
                check = true;

            } //else System.out.println("nam hash not equal");


        }
        return check;

    }

    static void storeAccount() {
        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();
        byte[] passSalt = null;
        byte[] nameSalt = null;
        String stringPassHash = null;
        String stringNameHash = null;
        //SecretKey passSecretKey = null;
        //SecretKey nameSecretKey = null;

        //get random salts
        try {
            SecureRandom secureRandom = SecureRandom.getInstance("DEFAULT", "BC");
            passSalt = new byte[32];
            secureRandom.nextBytes(passSalt);
            nameSalt = new byte[32];
            secureRandom.nextBytes(nameSalt);
            //System.out.println("passsaltvalue: " + Hex.toHexString(passSalt));
            //System.out.println("namesaltvalue: " + Hex.toHexString(nameSalt));
            model.setNameSalt(nameSalt);
            model.setPassSalt(passSalt);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }


        //hash pw, name
        if (passSalt != null && nameSalt != null) {
            //nameSecretKey = getPBKDHashKey(nameBytes, nameSalt);
            stringNameHash = Base64.toBase64String(Objects.requireNonNull(getPBKDHashKey(nameBytes, nameSalt)).getEncoded());
            stringPassHash = Base64.toBase64String(Objects.requireNonNull(getPBKDHashKey(passBytes, passSalt)).getEncoded());

          //  stringNameHash =  Hex.toHexString(Objects.requireNonNull(getPBKDHashKey(nameBytes, nameSalt)).getEncoded());
           // stringPassHash =  Hex.toHexString(Objects.requireNonNull(getPBKDHashKey(passBytes, passSalt)).getEncoded());

            //System.out.println("passkey hashvalue: " + stringPassHash);
            //System.out.println("passkey hashvalue: " + stringNameHash);
            //System.out.println("passkeyhexvalue: " + Hex.toHexString(stringPassHash.getBytes()));
        }

        String outFile = Hex.toHexString(Objects.requireNonNull(stringNameHash).getBytes()) + "." + "acc";
        String outString = Hex.toHexString(passSalt) + "," + Hex.toHexString(nameSalt) + "," + Hex.toHexString(stringPassHash.getBytes());

        //System.out.println("hex dehex: " + MessageDigest.isEqual(nameSalt, Hex.decode(Hex.toHexString(nameSalt))));

        byte[] accountData = outString.getBytes();
        FileUtils.write(outFile, accountData);
    }

    private static SecretKey getPBKDHashKey(char[] chars, byte[] salt) {
        var iterations = 5000; //hardcoded for now, could be settings
        var keyLen = 128;

        try {
            PBEKeySpec keySpec = new PBEKeySpec(chars, salt, iterations, keyLen);
// specifying data for key derivation
            SecretKeyFactory factory =
                    SecretKeyFactory.getInstance("PBKDF2WITHHMACSHA256", "BC");
// specifying algorithm for key derivation
            SecretKey key = factory.generateSecret(keySpec);
// the actual key derivation with iterated hashing
// key may now be passed to Cipher.init() (which accepts instances of interface SecretKey)
            if (key != null) {
                return key;
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

}
