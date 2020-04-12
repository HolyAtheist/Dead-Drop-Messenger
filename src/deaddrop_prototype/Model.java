package deaddrop_prototype;

import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;

import java.util.List;

public class Model {

    private StringProperty name = new SimpleStringProperty();
    public final StringProperty nameProperty() {
        return this.name;
    }
    public final String getName() { return this.nameProperty().get(); }
    public final void setName(String name) { this.nameProperty().set(name); }

    private StringProperty pass = new SimpleStringProperty();
    public final StringProperty passProperty() {
        return this.pass;
    }
    public final String getPass() {
        return this.passProperty().get();
    }
    public final void setPass(String pass) {
        this.passProperty().set(pass);
    }

    private byte[] passSalt = null;
    public final byte[] getPassSalt() {
        return this.passSalt;
    }
    public final void setPassSalt(byte[] salt) { this.passSalt = salt; }

    private byte[] nameSalt = null;
    public final byte[] getNameSalt() {
        return this.nameSalt;
    }
    public final void setNameSalt(byte[] salt) {
        this.nameSalt = salt;
    }


    ///conf
    private StringProperty protocol = new SimpleStringProperty();
    public final StringProperty protocolProperty() {
        return this.protocol;
    }
    public final String getProtocol() { return this.protocolProperty().get(); }
    public final void setProtocol(String name) { this.protocolProperty().set(name); }

    private StringProperty baseUrl = new SimpleStringProperty();
    public final StringProperty baseUrlProperty() {
        return this.baseUrl;
    }
    public final String getBaseUrl() { return this.baseUrlProperty().get(); }
    public final void setBaseUrl(String name) { this.baseUrlProperty().set(name); }

    private StringProperty idUrl = new SimpleStringProperty();
    public final StringProperty idUrlProperty() {
        return this.idUrl;
    }
    public final String getIdUrl() { return this.idUrlProperty().get(); }
    public final void setIdUrl(String name) { this.idUrlProperty().set(name); }
    ///


    private MessageObject messageObject = new MessageObject();
    public class MessageObject {
        private StringProperty message = new SimpleStringProperty();
        private StringProperty status = new SimpleStringProperty();
    }
    public final StringProperty messageProperty() { return messageObject.message; }
    public final String getMessage() { return this.messageProperty().get(); }
    public final void setMessage(String name) { this.messageProperty().set(name); }

    public final StringProperty statusProperty() {
        return messageObject.status;
    }
    public final String getStatus() { return this.statusProperty().get(); }
    public final void setStatus(String name) { this.statusProperty().set(name); }


    // public final ObservableList<CharSequence> getMessage() {
   //     return this.message;
   // }

   // public final void setMessage(ObservableList<CharSequence> msg) {
   //     this.message = msg;
   // }

   // public final byte[] getMessageBytes() {
       // return String.join("\n", this.getMessage()).getBytes();
  //  }


}
