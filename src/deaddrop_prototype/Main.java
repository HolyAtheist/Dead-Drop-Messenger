package deaddrop_prototype;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) {
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Model model = new Model();
        Controller controller = new Controller(model);
        IOLocalController ioLocalController = new IOLocalController(model);
        IODeadDropController ioDeadDropController = new IODeadDropController(model);
        View view = new View(controller, ioLocalController, ioDeadDropController, model);

        primaryStage.setTitle("DDM");

        // Create a scene with registration form grid pane as the root node
        Scene ddmStartup = new Scene(view.asParent(), 800, 500);

        // Set the scene in primary stage
        primaryStage.setScene(ddmStartup);

        primaryStage.show();
    }


    public static void main(String[] args) {
        launch(args);
    }
}