package deaddrop_prototype;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.json.Json;
import javax.json.JsonObject;
import javax.ws.rs.client.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Objects;

public class IODeadDropController {
    private static Model model;
    //private static Controller controller;

    public IODeadDropController(Model model) {
        this.model = model;
    }


    static void storeMessageDeadDrop() {
        //encrypt and save message

        //need to join charsequence list with newlines in between
        byte[] textArea = String.join("\n", Controller.getMess()).getBytes();

        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();
        byte[] passSalt = model.getNameSalt();
        byte[] nameSalt = model.getPassSalt();

        SecretKey passSecretKey;
        byte[] encryptedMessage = null;

        String protocol = model.getProtocol(); //"https://";
        String baseUrl = model.getBaseUrl(); //"jsonblob.com/api/jsonBlob/";
        String idUrl = model.getIdUrl(); //"23990876-7cc3-11ea-8070-5741ae0a9329";

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

        //prepare data and build json with encrypted data
        String stringNameHashCalculated = Hex.toHexString(Base64.toBase64String(Objects.requireNonNull(CryptUtils.getPBKDHashKey(nameBytes, nameSalt)).getEncoded()).getBytes());

        JsonObject value = Json.createObjectBuilder()
                .add("name", stringNameHashCalculated)
                .add("iv", Base64.toBase64String(generatedIV))
                .add("aes", Base64.toBase64String(Objects.requireNonNull(encryptedMessage))).build();

        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(protocol+baseUrl+idUrl); //build url
        Invocation.Builder invocationBuilder =  target.request(MediaType.APPLICATION_JSON);
        Response response = invocationBuilder.put(Entity.entity(value, MediaType.APPLICATION_JSON));

        if (response.getStatus()==200){
            Controller.updateStatus("Message seems to have been stored ok!");
        } else Controller.updateStatus("Problem storing message, status code: "+String.valueOf(response.getStatus()));

    }


    static void retrieveMessageDeadDrop() {
        //load and decrypt message for current account

        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();
        byte[] passSalt = model.getNameSalt();
        byte[] nameSalt = model.getPassSalt();

        SecretKey passSecretKey;
        byte[] decryptedBytes = new byte[0];

        String protocol = model.getProtocol(); //"https://";
        String baseUrl = model.getBaseUrl(); //"jsonblob.com/api/jsonBlob/";
        String idUrl = model.getIdUrl(); //"23990876-7cc3-11ea-8070-5741ae0a9329";

        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(protocol+baseUrl+idUrl); //build url
        Response response = target.request(MediaType.APPLICATION_JSON_TYPE).get(); //GET the url and store response

        JsonObject str2 = response.readEntity(JsonObject.class); //parse response json data

        //if code 200/ok, try to get encrypted data and decrypt
        if (response.getStatus()==200) {
            String name = str2.getString("name");
            String iv = str2.getString("iv");
            String aes = str2.getString("aes");

            byte[] readIV = Base64.decode(iv);
            byte[] readEncryptedMessage = Base64.decode(aes);

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
        //}
       // if (response.getStatus()==200){
            Controller.updateStatus("Message seems to have been retrieved ok!");
            Controller.updateMess(new String(decryptedBytes));
        } else Controller.updateStatus("Problem retrieving message, status code: "+String.valueOf(response.getStatus()));

    }

}
