package deaddrop_prototype;

import javafx.collections.ObservableList;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.json.Json;
import javax.json.JsonObject;
import javax.ws.rs.client.*;
import javax.ws.rs.core.GenericEntity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.Serializable;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class IONonLocalController {
    private static Model model;

    public IONonLocalController(Model model) {
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


        Client client = ClientBuilder.newClient();
        //query params: ?q=Turku&cnt=10&mode=json&units=metric
        //https://dog.ceo/api/breeds/list/all
        //http://svatky.adresa.info/json?date=0808

        //https://delighted.com/docs/api
        //key CCqqD4LC3E9lD3iNJB01NzbHtaPO7MiF


        WebTarget target = client.target("https://jsonblob.com/api/jsonBlob/23990876-7cc3-11ea-8070-5741ae0a9329");
               // .queryParam("date", "0808");
                //.queryParam("mode", "json")
               // .queryParam("units", "metric");
        String stringtest = target.toString();
        Response req = target.request(MediaType.APPLICATION_JSON_TYPE)
                .get();
        int status = req.getStatus();
        JsonObject str2 = req.readEntity(JsonObject.class); //get response json data
        System.out.println(stringtest);
        System.out.println(req);
        System.out.println(str2);
        System.out.println(status);

        String name = str2.getString("name");
        String iv = str2.getString("iv");
        String aes = str2.getString("aes");

        //return str3;
        
        //read .iv and .aes files in current account
     //   String stringNameHashCalculated = Hex.toHexString(Base64.toBase64String(Objects.requireNonNull(getPBKDHashKey(nameBytes, nameSalt)).getEncoded()).getBytes());
     //   byte[] readIV = Base64.decode(FileUtils.readAllBytes(stringNameHashCalculated + ".iv"));
     //   byte[] readEncryptedMessage = Base64.decode(FileUtils.readAllBytes(stringNameHashCalculated + ".aes"));


        byte[] readIV = Base64.decode(iv);
        byte[] readEncryptedMessage = Base64.decode(aes);
        
        //get SecretKey
        passSecretKey = Objects.requireNonNull(getPBKDHashKey(passBytes, passSalt));

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
        SecureRandom secureRandom = null;
        try {
            secureRandom = SecureRandom.getInstance("DEFAULT", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        byte[] generatedIV = new byte[16];
        assert secureRandom != null;
        secureRandom.nextBytes(generatedIV);
        IvParameterSpec ivParams = new IvParameterSpec(generatedIV);

        //get SecretKey
        passSecretKey = Objects.requireNonNull(getPBKDHashKey(passBytes, passSalt));

        //do encryption
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, passSecretKey, ivParams);
            encryptedMessage = cipher.doFinal(textArea);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        //prepare data and write files .iv and encrypted .aes
        String stringNameHashCalculated = Hex.toHexString(Base64.toBase64String(Objects.requireNonNull(getPBKDHashKey(nameBytes, nameSalt)).getEncoded()).getBytes());
        byte[] iv = Base64.toBase64String(generatedIV).getBytes();

        //String ivOutFile = stringNameHashCalculated + "." + "iv";
       // FileUtils.write(ivOutFile, iv);

       // String outTextArea = stringNameHashCalculated + "." + "aes";
        //FileUtils.write(outTextArea, Base64.toBase64String(Objects.requireNonNull(encryptedMessage)).getBytes());

        JsonObject value = Json.createObjectBuilder()
                .add("name", stringNameHashCalculated)
                .add("iv", Base64.toBase64String(generatedIV))
                .add("aes", Base64.toBase64String(Objects.requireNonNull(encryptedMessage))).build();

       // List s = new ArrayList();
      //  s.add("Test First Name !!!");
      //  s.add("Test Last Name!!!");


       // GenericEntity<List<?>> genericEntity = new GenericEntity<List<?>> (s)  {};
       // Response.status(Response.Status.BAD_REQUEST).entity(genericEntity).build();

        Client client = ClientBuilder.newClient();
        WebTarget target = client.target("https://jsonblob.com/api/jsonBlob/23990876-7cc3-11ea-8070-5741ae0a9329");
        Invocation.Builder invocationBuilder =  target.request(MediaType.APPLICATION_JSON);
        Response response = invocationBuilder.put(Entity.entity(value, MediaType.APPLICATION_JSON));

        JsonObject employee = response.readEntity(JsonObject.class);

        System.out.println(response.getStatus());
        System.out.println(employee);

    }



   /* static boolean retrieveAccount() {
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

            stringNameHashCalculated = Base64.toBase64String(Objects.requireNonNull(getPBKDHashKey(nameBytes, nameSaltRetrieved)).getEncoded());
            stringPassHashCalculated = Base64.toBase64String(Objects.requireNonNull(getPBKDHashKey(passBytes, passSaltRetrieved)).getEncoded());

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
            stringNameHash = Base64.toBase64String(Objects.requireNonNull(getPBKDHashKey(nameBytes, nameSalt)).getEncoded());
            stringPassHash = Base64.toBase64String(Objects.requireNonNull(getPBKDHashKey(passBytes, passSalt)).getEncoded());
        }

        //build .acc account file and write it using hashed name as filename
        String outFile = Hex.toHexString(Objects.requireNonNull(stringNameHash).getBytes()) + "." + "acc";
        String outString = Hex.toHexString(passSalt) + "," + Hex.toHexString(nameSalt) + "," + Hex.toHexString(stringPassHash.getBytes());
        byte[] accountData = outString.getBytes();
        FileUtils.write(outFile, accountData);
    }*/

    private static SecretKey getPBKDHashKey(char[] chars, byte[] salt) {
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
