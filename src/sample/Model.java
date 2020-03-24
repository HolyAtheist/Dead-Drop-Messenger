package sample;

import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

public class Model {
   // private ObservableList<CharSequence> message = FXCollections.observableArrayList();
    private StringProperty name = new SimpleStringProperty();
    private StringProperty pass = new SimpleStringProperty();
   // private SecretKey passSecretKey = null;
   // private SecretKey nameSecretKey = null;
    private byte[] passSalt = null;
    private byte[] nameSalt = null;


    public final StringProperty nameProperty() {
        return this.name;
    }

    public final String getName() {
        //System.out.println("model name value get: " + this.nameProperty().get());
        return this.nameProperty().get();
    }

    public final void setName(String name) {
        //System.out.println("model name value set: " + this.nameProperty().get());
        this.nameProperty().set(name);
    }

    public final StringProperty passProperty() {
        return this.pass;
    }

    public final String getPass() {
        return this.passProperty().get();
    }

    public final void setPass(String pass) {
        this.passProperty().set(pass);
    }


    public final byte[] getPassSalt() {
        return this.passSalt;
    }

    public final void setPassSalt(byte[] salt) { this.passSalt = salt; }

    public final byte[] getNameSalt() {
        return this.nameSalt;
    }

    public final void setNameSalt(byte[] salt) {
        this.nameSalt = salt;
    }

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
