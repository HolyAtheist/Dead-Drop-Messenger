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
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

public class Controller {
    private final Model model ;

    public Controller(Model model) {
        this.model = model ;
    }

    public void updateName(String name) {
        //System.out.println("updating model name: " + name);
        model.setName(name);
    }

    public void updatePass(String pass) {
        //System.out.println("updating model pass: " + pass);
        model.setPass(pass);
    }

    public void updateMess(String newText) {
        model.setMessage(newText);
    }

    public void updateStatus(String newText) {
        model.setStatus(newText);
    }

    public String getMess() {
        return model.getMessage();
    }

    public String getStatus() {
        return model.getStatus();
    }


    void storeMessageDeadDrop() {
        //encrypt and save message

        //need to join charsequence list with newlines in between
        byte[] textArea = String.join("\n", this.getMess()).getBytes();

        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();
        byte[] passSalt = model.getNameSalt();
        byte[] nameSalt = model.getPassSalt();

        SecretKey passSecretKey;
        byte[] encryptedMessage = null;

        String protocol = "https://";
        String baseUrl = "jsonblob.com/api/jsonBlob/";
        String idUrl = "23990876-7cc3-11ea-8070-5741ae0a9329";

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
        //byte[] iv = Base64.toBase64String(generatedIV).getBytes();

        JsonObject value = Json.createObjectBuilder()
                .add("name", stringNameHashCalculated)
                .add("iv", Base64.toBase64String(generatedIV))
                .add("aes", Base64.toBase64String(Objects.requireNonNull(encryptedMessage))).build();

        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(protocol+baseUrl+idUrl); //build url
        Invocation.Builder invocationBuilder =  target.request(MediaType.APPLICATION_JSON);
        Response response = invocationBuilder.put(Entity.entity(value, MediaType.APPLICATION_JSON));

        if (response.getStatus()==200){
            this.updateStatus("Message seems to have been stored ok!");
        } else this.updateStatus("Problem storing message, status code: "+String.valueOf(response.getStatus()));

    }



    void retrieveMessageDeadDrop() {
        //load and decrypt message for current account

        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();
        byte[] passSalt = model.getNameSalt();
        byte[] nameSalt = model.getPassSalt();

        SecretKey passSecretKey;
        byte[] decryptedBytes = new byte[0];

        String protocol = "https://";
        String baseUrl = "jsonblob.com/api/jsonBlob/";
        String idUrl = "23990876-7cc3-11ea-8070-5741ae0a9329";

        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(protocol+baseUrl+idUrl); //build url
        //String stringtest = target.toString();
        Response response = target.request(MediaType.APPLICATION_JSON_TYPE).get(); //GET the url

        int status = response.getStatus();
        JsonObject str2 = response.readEntity(JsonObject.class); //get response json data

        if (response.getStatus()==200) {
            String name = str2.getString("name");
            String iv = str2.getString("iv");
            String aes = str2.getString("aes");

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
        }
        if (response.getStatus()==200){
            this.updateStatus("Message seems to have been retrieved ok!");
            this.updateMess(new String(decryptedBytes));
        } else this.updateStatus("Problem retrieving message, status code: "+String.valueOf(response.getStatus()));

    }

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
