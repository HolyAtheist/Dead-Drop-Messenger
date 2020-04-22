package deaddrop_prototype;

//// basic getter-setter controller
public class Controller {
    private static Model model;

    public Controller(Model model) {
        this.model = model;
    }

    public static void updateName(String name) {
        model.setName(name);
    }

    public static void updatePass(String pass) {
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

    public static String getStatus() {
        return model.getStatus();
    }


    public static void updateProtocol(String newText) {
        model.setProtocol(newText);
    }

    public static void updateBaseUrl(String newText) {
        model.setBaseUrl(newText);
    }

    public static void updateIdUrl(String newText) {
        model.setIdUrl(newText);
    }

    public static String getProtocol() {
        return model.getProtocol();
    }

    public static String getBaseUrl() {
        return model.getBaseUrl();
    }

    public static String getIdUrl() {
        return model.getIdUrl();
    }

    public static String getIdHeader() {
        return model.getIdHeader();
    }

    public static void updateIdHeader(String newText) {
        model.setIdHeader(newText);
    }
}
