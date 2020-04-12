package deaddrop_prototype;

import javafx.collections.ObservableList;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.util.Objects;

public class IOLocalController {
    private static Model model;

    public IOLocalController(Model model) {
        this.model = model;
    }

    static String retrieveMessage() {
        //load and decrypt message for current account

        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();
        byte[] passSalt = model.getNameSalt();
        byte[] nameSalt = model.getPassSalt();

        SecretKey passSecretKey;
        byte[] decryptedBytes = new byte[0];

        //read .iv and .aes files in current account
        String stringNameHashCalculated = Hex.toHexString(Base64.toBase64String(Objects.requireNonNull(CryptUtils.getPBKDHashKey(nameBytes, nameSalt)).getEncoded()).getBytes());
        byte[] readIV = Base64.decode(FileUtils.readAllBytes(stringNameHashCalculated + ".iv"));
        byte[] readEncryptedMessage = Base64.decode(FileUtils.readAllBytes(stringNameHashCalculated + ".aes"));

        //get SecretKey
        passSecretKey = Objects.requireNonNull(CryptUtils.getPBKDHashKey(passBytes, passSalt));

        //input iv
        IvParameterSpec ivParams = new IvParameterSpec(readIV);

        //do decryption
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, passSecretKey, ivParams);
            decryptedBytes = cipher.doFinal(readEncryptedMessage);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchPaddingException | NoSuchProviderException e) {
            e.printStackTrace();
        }

        //return decrypted message
        return new String(decryptedBytes);

    }

    static void storeMessage(ObservableList<CharSequence> paragraph) {
        //encrypt and save message

        //need to join charsequence list with newlines in between
        byte[] textArea = String.join("\n", paragraph).getBytes();

        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();
        byte[] passSalt = model.getNameSalt();
        byte[] nameSalt = model.getPassSalt();

        SecretKey passSecretKey;
        byte[] encryptedMessage = null;

        ////encrypt message

        //get random iv
        byte[] generatedIV = CryptUtils.generateSecureIV();
        IvParameterSpec ivParams = new IvParameterSpec(generatedIV);

        //get SecretKey
        passSecretKey = Objects.requireNonNull(CryptUtils.getPBKDHashKey(passBytes, passSalt));

        //do encryption
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, passSecretKey, ivParams);
            encryptedMessage = cipher.doFinal(textArea);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        //prepare data and write files .iv and encrypted .aes
        String stringNameHashCalculated = Hex.toHexString(Base64.toBase64String(Objects.requireNonNull(CryptUtils.getPBKDHashKey(nameBytes, nameSalt)).getEncoded()).getBytes());
        byte[] iv = Base64.toBase64String(generatedIV).getBytes();

        String ivOutFile = stringNameHashCalculated + "." + "iv";
        FileUtils.write(ivOutFile, iv);

        String outTextArea = stringNameHashCalculated + "." + "aes";
        FileUtils.write(outTextArea, Base64.toBase64String(Objects.requireNonNull(encryptedMessage)).getBytes());
    }



    static boolean retrieveAccount() {
        //try to find a matching account
        //note: currently possible to have accounts with same name and password
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

        //get all files with extension .acc
        String currentDirectory = System.getProperty("user.dir");
        String[] files;
        files = FileUtils.getAllFileNames(currentDirectory, "acc");
        //System.out.println(Arrays.toString(files));

        //loop through all .acc files
        for (String filename : files
        ) {
            String name = filename.substring(0, filename.lastIndexOf('.'));
            stringNameHashRetrieved = name;
            byte[] fileBytes = FileUtils.readAllBytes(name + ".acc");
            String fileString = new String(fileBytes);
            //get content separated by commas
            String[] fileContents = fileString.split(",");
            stringPassSaltRetrieved = fileContents[0];
            stringNameSaltRetrieved = fileContents[1];
            stringPassHashRetrieved = fileContents[2];

            passSaltRetrieved = Hex.decode(stringPassSaltRetrieved);
            nameSaltRetrieved = Hex.decode(stringNameSaltRetrieved);

            stringNameHashCalculated = Base64.toBase64String(Objects.requireNonNull(CryptUtils.getPBKDHashKey(nameBytes, nameSaltRetrieved)).getEncoded());
            stringPassHashCalculated = Base64.toBase64String(Objects.requireNonNull(CryptUtils.getPBKDHashKey(passBytes, passSaltRetrieved)).getEncoded());

            //compare hashes of name and pass from login with current .acc file
            if (MessageDigest
                    .isEqual(Hex.toHexString(stringNameHashCalculated.getBytes()).getBytes(),
                            stringNameHashRetrieved.getBytes()) &&
                    MessageDigest
                            .isEqual(Hex.toHexString(stringPassHashCalculated.getBytes()).getBytes(),
                                    stringPassHashRetrieved.getBytes())) {
                //if login/password matched
                //store retrieved salts in model for later enc/dec
                model.setNameSalt(nameSaltRetrieved);
                model.setPassSalt(passSaltRetrieved);
                check = true;
            } //else they didn't match
        }
        //return true if (at least one) account matched
        return check;

    }

    static void storeAccount() {
        //create a new account
        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();
        byte[] passSalt = null;
        byte[] nameSalt = null;
        String stringPassHash = null;
        String stringNameHash = null;

        //get random salts
        try {
            SecureRandom secureRandom = SecureRandom.getInstance("DEFAULT", "BC");
            passSalt = new byte[32];
            secureRandom.nextBytes(passSalt);
            nameSalt = new byte[32];
            secureRandom.nextBytes(nameSalt);
            //store salts in model for later enc/dec
            model.setNameSalt(nameSalt);
            model.setPassSalt(passSalt);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }

        //hash password, name
        if (passSalt != null && nameSalt != null) {
            stringNameHash = Base64.toBase64String(Objects.requireNonNull(CryptUtils.getPBKDHashKey(nameBytes, nameSalt)).getEncoded());
            stringPassHash = Base64.toBase64String(Objects.requireNonNull(CryptUtils.getPBKDHashKey(passBytes, passSalt)).getEncoded());
        }

        //build .acc account file and write it using hashed name as filename
        String outFile = Hex.toHexString(Objects.requireNonNull(stringNameHash).getBytes()) + "." + "acc";
        String outString = Hex.toHexString(passSalt) + "," + Hex.toHexString(nameSalt) + "," + Hex.toHexString(stringPassHash.getBytes());
        byte[] accountData = outString.getBytes();
        FileUtils.write(outFile, accountData);
    }



}
