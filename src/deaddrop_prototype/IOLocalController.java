package deaddrop_prototype;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.io.StringReader;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
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
        byte[] nameSalt = model.getNameSalt();
        byte[] passSalt = model.getPassSalt();

        SecretKey passSecretKey;
        byte[] decryptedBytes;

        //read .iv and .aes files in current account
        String stringNameHashCalculated = Hex.toHexString(Base64.toBase64String(Objects.requireNonNull(CryptUtils.getPBKDHashKey(nameBytes, nameSalt)).getEncoded()).getBytes());
        byte[] readIV = Base64.decode(FileUtils.readAllBytes(stringNameHashCalculated + "." + model.messageFilenameIVExtension));
        byte[] readEncryptedMessage = Base64.decode(FileUtils.readAllBytes(stringNameHashCalculated + "." + model.messageFilenameEncryptedExtension));

        //calculate SecretKey
        passSecretKey = Objects.requireNonNull(CryptUtils.getPBKDHashKey(passBytes, passSalt));

        //input retrieved iv
        IvParameterSpec ivParams = new IvParameterSpec(readIV);

        //do decryption -- using encrypted message, calculated secretkey, retrieved iv
        decryptedBytes = CryptUtils.crypt(readEncryptedMessage, passSecretKey, ivParams, Cipher.DECRYPT_MODE);

        //return decrypted message
        return new String(decryptedBytes);

    }

    static void storeMessage() {
        //encrypt and save message

        //need to join charsequence list with newlines in between
        byte[] textArea = String.join("\n", Controller.getMess()).getBytes();

        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();
        byte[] nameSalt = model.getNameSalt();
        byte[] passSalt = model.getPassSalt();

        SecretKey passSecretKey;
        byte[] encryptedMessage;

        ////encrypt message

        //get random iv
        byte[] generatedIV = CryptUtils.generateSecureIV();
        IvParameterSpec ivParams = new IvParameterSpec(generatedIV);

        //get SecretKey
        passSecretKey = Objects.requireNonNull(CryptUtils.getPBKDHashKey(passBytes, passSalt));

        //do encryption
        encryptedMessage = CryptUtils.crypt(textArea, passSecretKey, ivParams, Cipher.ENCRYPT_MODE);

        //prepare data and write files .iv and encrypted .aes
        String stringNameHashCalculated = Hex.toHexString(Base64.toBase64String(Objects.requireNonNull(CryptUtils.getPBKDHashKey(nameBytes, nameSalt)).getEncoded()).getBytes());
        System.out.println(stringNameHashCalculated);
        byte[] iv = Base64.toBase64String(generatedIV).getBytes();

        String ivOutFile = stringNameHashCalculated + "." + model.messageFilenameIVExtension;
        FileUtils.write(ivOutFile, iv);

        String outTextArea = stringNameHashCalculated + "." + model.messageFilenameEncryptedExtension;
        FileUtils.write(outTextArea, Base64.toBase64String(Objects.requireNonNull(encryptedMessage)).getBytes());
    }


    static boolean retrieveAccount() {
        //try to find a matching account
        //note: currently possible to have accounts with same name and password (due to the random salt)
        char[] nameBytes = model.getName().toCharArray(); // name we got from login screen field
        char[] passBytes = model.getPass().toCharArray(); // password we got from login screen field

        String stringNameHashCalculated;
        String stringPassHashCalculated;

        String stringNameHashRetrieved;
        String stringPassHashRetrieved;
        String stringPassSaltRetrieved;
        String stringNameSaltRetrieved;
        byte[] passSaltRetrieved;
        byte[] nameSaltRetrieved;

        boolean check = false;

        //get all files with extension .acc
        String currentDirectory = System.getProperty("user.dir");
        String[] files;
        files = FileUtils.getAllFileNames(currentDirectory, model.accountFilenameExtension);

        //loop through all .acc files
        for (String filename : files
        ) {
            String name = filename.substring(0, filename.lastIndexOf('.'));
            stringNameHashRetrieved = name;
            byte[] fileBytes = FileUtils.readAllBytes(name + "." + model.accountFilenameExtension);
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
        String outFile = Hex.toHexString(Objects.requireNonNull(stringNameHash).getBytes()) + "." + model.accountFilenameExtension;
        String outString = Hex.toHexString(passSalt) + "," + Hex.toHexString(nameSalt) + "," + Hex.toHexString(stringPassHash.getBytes());
        byte[] accountData = outString.getBytes();
        FileUtils.write(outFile, accountData);
    }


    public void storeConfig() {
        //encrypt and save config

        // config is stored as encrypted json data in a .con file
        // as well as the random iv in a .civ file

        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();
        byte[] nameSalt = model.getNameSalt();
        byte[] passSalt = model.getPassSalt();

        SecretKey passSecretKey;
        byte[] encryptedMessage;

        if (model.getIdUrl().getBytes() == null) { model.setIdUrl("");}
        if (model.getProtocol().getBytes() == null) { model.setProtocol("");}
        if (model.getBaseUrl().getBytes() == null) { model.setBaseUrl("");}
        if (model.getIdHeader().getBytes() == null) { model.setIdHeader("");}

        JsonObject jsonConfig = Json.createObjectBuilder()
                .add(model.configProtocolJsonName, Base64.toBase64String(model.getProtocol().getBytes()))
                .add(model.configBaseUrlJsonName, Base64.toBase64String(model.getBaseUrl().getBytes()))
                .add(model.configIdUrlJsonName, Base64.toBase64String(model.getIdUrl().getBytes()))
                .add(model.configIdHeaderJsonName, Base64.toBase64String(model.getIdHeader().getBytes())).build();

        ////encrypt message

        //get random iv
        byte[] generatedIV = CryptUtils.generateSecureIV();
        IvParameterSpec ivParams = new IvParameterSpec(generatedIV);

        //get SecretKey
        passSecretKey = Objects.requireNonNull(CryptUtils.getPBKDHashKey(passBytes, passSalt));

        byte[] data = jsonConfig.toString().getBytes();

        //do encryption
        encryptedMessage = CryptUtils.crypt(data, passSecretKey, ivParams, Cipher.ENCRYPT_MODE);

        //prepare data and write files .iv and encrypted .aes
        String stringNameHashCalculated = Hex.toHexString(Base64.toBase64String(Objects.requireNonNull(CryptUtils.getPBKDHashKey(nameBytes, nameSalt)).getEncoded()).getBytes());
        byte[] iv = Base64.toBase64String(generatedIV).getBytes();

        String ivOutFile = stringNameHashCalculated + "." + model.configFilenameIVExtension;
        FileUtils.write(ivOutFile, iv);

        String outTextArea = stringNameHashCalculated + "." + model.configFilenameConfigExtension;
        FileUtils.write(outTextArea, Base64.toBase64String(Objects.requireNonNull(encryptedMessage)).getBytes());

    }

    public void retrieveConfig() {
        //try to find a matching config

        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();
        byte[] nameSalt = model.getNameSalt();
        byte[] passSalt = model.getPassSalt();

        SecretKey passSecretKey;
        byte[] decryptedBytes = new byte[0];

        //try to get config files
        byte[] readIV = new byte[0];
        byte[] readEncryptedMessage = new byte[0];

        //read .civ and .con files (encrypted configuration) in current account
        String stringNameHashCalculated = Hex.toHexString(Base64.toBase64String(Objects.requireNonNull(CryptUtils.getPBKDHashKey(nameBytes, nameSalt)).getEncoded()).getBytes());

        readIV = Base64.decode(FileUtils.readAllBytes(stringNameHashCalculated + "." + model.configFilenameIVExtension));
        readEncryptedMessage = Base64.decode(FileUtils.readAllBytes(stringNameHashCalculated + "." + model.configFilenameConfigExtension));

        //proceed if it appears we got iv
        if (readIV != null && readIV.length == 16) {

            //get SecretKey
            passSecretKey = Objects.requireNonNull(CryptUtils.getPBKDHashKey(passBytes, passSalt));

            //input iv
            IvParameterSpec ivParams = new IvParameterSpec(readIV);

            //try to do decryption
            decryptedBytes = CryptUtils.crypt(readEncryptedMessage, passSecretKey, ivParams, Cipher.DECRYPT_MODE);

            String json = new String(decryptedBytes);

            JsonReader jsonReader = Json.createReader(new StringReader(json));
            JsonObject object = jsonReader.readObject();
            jsonReader.close();

            String protocol = new String(Base64.decode(object.getString(model.configProtocolJsonName)));
            String baseUrl = new String(Base64.decode(object.getString(model.configBaseUrlJsonName)));
            String idUrl = new String(Base64.decode(object.getString(model.configIdUrlJsonName)));
            String idHeader = new String(Base64.decode(object.getString(model.configIdHeaderJsonName)));

            model.setProtocol(protocol);
            model.setBaseUrl(baseUrl);
            model.setIdUrl(idUrl);
            model.setIdHeader(idHeader);
        }

    }
}
