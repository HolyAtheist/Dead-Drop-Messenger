package deaddrop_prototype;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.json.Json;
import javax.json.JsonObject;
import javax.ws.rs.client.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Objects;

public class IODeadDropController {
    private static Model model;

    public IODeadDropController(Model model) {
        this.model = model;
    }


    static void storeMessageDeadDrop() {
        //encrypt and save message

        //need to join charsequence list with newlines in between when getting text from javafx TextArea
        byte[] textArea = String.join("\n", Controller.getMess()).getBytes();

        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();
        byte[] passSalt = model.getNameSalt();
        byte[] nameSalt = model.getPassSalt();

        SecretKey passSecretKey;
        byte[] encryptedMessage;

        // note: the only website supported/tested for now is jsonblob.com
        String protocol = model.getProtocol(); //"https://";
        String baseUrl = model.getBaseUrl(); //"jsonblob.com/api/jsonBlob/";
        String idUrl = model.getIdUrl(); //"23990876-7cc3-11ea-8070-5741ae0a9329";

        ////encrypt message

        //get new random iv
        byte[] generatedIV = CryptUtils.generateSecureIV();
        IvParameterSpec ivParams = new IvParameterSpec(generatedIV);

        //calculate SecretKey
        passSecretKey = Objects.requireNonNull(CryptUtils.getPBKDHashKey(passBytes, passSalt));

        //do encryption
        encryptedMessage = CryptUtils.crypt(textArea, passSecretKey, ivParams, Cipher.ENCRYPT_MODE);

        //prepare data and build json with encrypted data
        String stringNameHashCalculated = Hex.toHexString(Base64.toBase64String(Objects.requireNonNull(CryptUtils.getPBKDHashKey(nameBytes, nameSalt)).getEncoded()).getBytes());

        //build json data
        JsonObject value = Json.createObjectBuilder()
                .add(model.deaddropNameJsonName, stringNameHashCalculated) // note: namehash is not currently used, could be used in the future for eg. a simple comparison between account name hashes
                .add(model.deaddropIVJsonName, Base64.toBase64String(generatedIV))
                .add(model.deaddropEncryptedJsonName, Base64.toBase64String(Objects.requireNonNull(encryptedMessage))).build();

        // build url and PUT (update) the dead drop data
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(protocol + baseUrl + idUrl); //build url
        Invocation.Builder invocationBuilder = target.request(MediaType.APPLICATION_JSON);
        Response response = invocationBuilder.put(Entity.entity(value, MediaType.APPLICATION_JSON));

        if (response.getStatus() == 200) {
            Controller.updateStatus("Message seems to have been stored ok!");
        } else Controller.updateStatus("Problem storing message, status code: " + response.getStatus());

    }


    static void retrieveMessageDeadDrop() {
        //load and decrypt message for current account

        char[] nameBytes = model.getName().toCharArray();
        char[] passBytes = model.getPass().toCharArray();
        byte[] passSalt = model.getNameSalt();
        byte[] nameSalt = model.getPassSalt();

        SecretKey passSecretKey;
        byte[] decryptedBytes;

        // note: the only website supported/tested for now is jsonblob.com
        String protocol = model.getProtocol(); //"https://";
        String baseUrl = model.getBaseUrl(); //"jsonblob.com/api/jsonBlob/";
        String idUrl = model.getIdUrl(); //"23990876-7cc3-11ea-8070-5741ae0a9329";

        //build url and GET from the address
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(protocol + baseUrl + idUrl); //build url
        Response response = target.request(MediaType.APPLICATION_JSON_TYPE).get(); //GET the url and store response

        JsonObject str2 = response.readEntity(JsonObject.class); //parse response json data

        ////if code 200/ok, try to get encrypted data and decrypt
        if (response.getStatus() == 200) {
            String name = str2.getString(model.deaddropNameJsonName); // note: name is not currently used, could be used in the future for eg. a simple comparison between account name hashes
            String iv = str2.getString(model.deaddropIVJsonName);
            String aes = str2.getString(model.deaddropEncryptedJsonName);

            byte[] readIV = new byte[0];
            byte[] readEncryptedMessage = new byte[0];

            try {
                readIV = Base64.decode(iv);
                readEncryptedMessage = Base64.decode(aes);
            } catch (Exception e) {
                //e.printStackTrace();
            }

            //proceed if it appears we got iv
            //could of course have more thorough error checking
            if (readIV != null && readIV.length == 16) {

                //get SecretKey
                passSecretKey = Objects.requireNonNull(CryptUtils.getPBKDHashKey(passBytes, passSalt));

                //input iv
                IvParameterSpec ivParams = new IvParameterSpec(readIV);

                //do decryption
                decryptedBytes = CryptUtils.crypt(readEncryptedMessage, passSecretKey, ivParams, Cipher.DECRYPT_MODE);

                Controller.updateStatus("Message seems to have been retrieved ok!");
                Controller.updateMess(new String(decryptedBytes));
            } else Controller.updateStatus("Problem decoding message ");
        } else
            Controller.updateStatus("Problem retrieving message, status code: " + response.getStatus());

    }

    static void getNewId() {
        //this method tries to get a new id -- the path to specific data on jsonblob
        // == a path to a new deaddrop
        // note: the only website supported/tested for now is jsonblob.com
        String protocol = model.getProtocol(); //"https://";
        String baseUrl = model.getBaseUrl(); //"jsonblob.com/api/jsonBlob/";
        String idHeader = model.getIdHeader(); //  X-jsonblob

        //build dummy json to POST (dummy data could be anything, here follows the layout of the real data)
        JsonObject value = Json.createObjectBuilder()
                .add(model.deaddropNameJsonName, "dummyname")
                .add(model.deaddropIVJsonName, "dummyiv")
                .add(model.deaddropEncryptedJsonName, "dummyaes").build();

        //build url and POST the dummy data
        Client client = ClientBuilder.newClient();
        WebTarget target = client.target(protocol + baseUrl); //build url
        Invocation.Builder invocationBuilder = target.request(MediaType.APPLICATION_JSON);
        Response response = invocationBuilder.post(Entity.entity(value, MediaType.APPLICATION_JSON));

        //if new path created ok, then get the path/blobid
        if (response.getStatus() == 201) {
            model.setIdUrl(response.getHeaderString(idHeader));
        } //else failed
    }
}
