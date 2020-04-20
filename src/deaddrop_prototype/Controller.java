package deaddrop_prototype;

//// basic getter-setter controller
public class Controller {
    private static Model model;

    public Controller(Model model) {
        this.model = model;
    }

    public void updateName(String name) {
        model.setName(name);
    }

    public void updatePass(String pass) {
        model.setPass(pass);
    }

    public static void updateMess(String newText) {
        model.setMessage(newText);
    }

    public static void updateStatus(String newText) {
        model.setStatus(newText);
    }

    public static String getMess() {
        return model.getMessage();
    }

    public String getStatus() {
        return model.getStatus();
    }


    public void updateProtocol(String newText) {
        model.setProtocol(newText);
    }

    public void updateBaseUrl(String newText) {
        model.setBaseUrl(newText);
    }

    public void updateIdUrl(String newText) {
        model.setIdUrl(newText);
    }

    public String getProtocol() {
        return model.getProtocol();
    }

    public String getBaseUrl() {
        return model.getBaseUrl();
    }

    public String getIdUrl() {
        return model.getIdUrl();
    }

    public String getIdHeader() {
        return model.getIdHeader();
    }

    public void updateIdHeader(String newText) {
        model.setIdHeader(newText);
    }
}
