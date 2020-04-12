package deaddrop_prototype;

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

}
