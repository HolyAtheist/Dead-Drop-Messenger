package deaddrop_prototype;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Model model = new Model();
        Controller controller = new Controller(model);
        IOLocalController ioLocalController = new IOLocalController(model);
        IONonLocalController ioNonLocalController = new IONonLocalController(model);
        //todo: have just one controller or several by proper method
        View view = new View(controller, model);

        primaryStage.setTitle("Startup Screen");

        // Create a scene with registration form grid pane as the root node
        Scene messStartup = new Scene(view.asParent(), 800, 500);

        // Set the scene in primary stage
        primaryStage.setScene(messStartup);

        primaryStage.show();
    }


    public static void main(String[] args) {
        launch(args);
    }
}