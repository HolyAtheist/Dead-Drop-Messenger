package sample;

import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.HPos;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.control.*;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.Priority;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.stage.Window;

import java.io.IOException;
import java.security.spec.InvalidKeySpecException;

public class View {
    private static GridPane gridPane;
    private static TextArea messField = new TextArea();
    private static TextField nameField = new TextField();
    private static PasswordField passwordField = new PasswordField();

    private static Controller controller;
    private static IOLocalController ioLocalController;
    private Model model;

    public View(Controller controller, Model model) {

        this.controller = controller;
        this.ioLocalController = ioLocalController;
        this.model = model;

        GridPane gridPane = createDefaultFormPane();

        loginSceneElements(gridPane);
    }

    public Parent asParent() {
        return gridPane;
    }

    public static GridPane createDefaultFormPane() {
        // Instantiate a new Grid Pane
        gridPane = new GridPane();

        // Position the pane at the center of the screen, both vertically and horizontally
        gridPane.setAlignment(Pos.CENTER);

        // Set a padding of 20px on each side
        gridPane.setPadding(new Insets(40, 40, 40, 40));

        // Set the horizontal gap between columns
        gridPane.setHgap(10);

        // Set the vertical gap between rows
        gridPane.setVgap(10);

        // Add Column Constraints

        // columnOneConstraints will be applied to all the nodes placed in column one.
        ColumnConstraints columnOneConstraints = new ColumnConstraints(100, 100, Double.MAX_VALUE);
        columnOneConstraints.setHalignment(HPos.RIGHT);

        // columnTwoConstraints will be applied to all the nodes placed in column two.
        ColumnConstraints columnTwoConstrains = new ColumnConstraints(200, 200, Double.MAX_VALUE);
        columnTwoConstrains.setHgrow(Priority.ALWAYS);

        gridPane.getColumnConstraints().addAll(columnOneConstraints, columnTwoConstrains);

        return gridPane;
    }

    public static void loginSceneElements(GridPane gridPane) {
        // Add Header
        Label headerLabel = new Label("Login or Create new account");
        headerLabel.setFont(Font.font("Arial", FontWeight.BOLD, 24));
        gridPane.add(headerLabel, 0, 0, 2, 1);
        GridPane.setHalignment(headerLabel, HPos.CENTER);
        GridPane.setMargin(headerLabel, new Insets(20, 0, 20, 0));

        // Add Name Label
        Label nameLabel = new Label("Name : ");
        gridPane.add(nameLabel, 0, 1);

        // Add Name Text Field
        //TextField nameField = new TextField();
        nameField.setPrefHeight(40);
        gridPane.add(nameField, 1, 1);
        nameField.textProperty().addListener((obs, oldText, newText) -> controller.updateName(newText));


        // Add Password Label
        Label passwordLabel = new Label("Password : ");
        gridPane.add(passwordLabel, 0, 3);

        // Add Password Field
        //PasswordField passwordField = new PasswordField();
        passwordField.setPrefHeight(40);
        gridPane.add(passwordField, 1, 3);
        passwordField.textProperty().addListener((obs, oldText, newText) -> controller.updatePass(newText));

        // Add Submit Button
        Button loginButton = new Button("Login");
        loginButton.setPrefHeight(40);
        //loginButton.setDefaultButton(true);
        loginButton.setPrefWidth(100);
        gridPane.add(loginButton, 1, 4, 2, 1);
        //GridPane.setHalignment(loginButton, HPos.CENTER);
        GridPane.setMargin(loginButton, new Insets(20, 0, 20, 0));

        // Add new account Button
        Button createNewAccountButton = new Button("Create New");
        createNewAccountButton.setPrefHeight(40);
        //createNewAccountButton.setDefaultButton(true);
        createNewAccountButton.setPrefWidth(100);
        gridPane.add(createNewAccountButton, 0, 4, 2, 1);
        //GridPane.setHalignment(createNewAccountButton, HPos.CENTER);
        GridPane.setMargin(createNewAccountButton, new Insets(20, 0, 20, 0));

        createNewAccountButton.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                if (nameField.getText().isEmpty()) {
                    showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "Please enter your name");
                    return;
                }
                if (passwordField.getText().isEmpty()) {
                    showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "Please enter a password");
                    return;
                }

                ioLocalController.storeAccount();

                // showAlert(Alert.AlertType.CONFIRMATION, gridPane.getScene().getWindow(), "Account created", "Welcome " + nameField.getText());
                gridPane.getChildren().clear();
                messageSceneElements(gridPane);

            }
        });

        loginButton.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                if (nameField.getText().isEmpty()) {
                    showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "Please enter your name");
                    return;
                }
                if (passwordField.getText().isEmpty()) {
                    showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "Please enter a password");
                    return;
                }

                if (ioLocalController.retrieveAccount()) {
                    //showAlert(Alert.AlertType.CONFIRMATION, gridPane.getScene().getWindow(), "Login", "Welcome " + nameField.getText());
                    gridPane.getChildren().clear();
                    messageSceneElements(gridPane);
                }
            }
        });
    }

    public static void messageSceneElements(GridPane gridPane) {
        // Add Header
        Label headerLabel = new Label("Message");
        headerLabel.setFont(Font.font("Arial", FontWeight.BOLD, 24));
        gridPane.add(headerLabel, 0, 0, 2, 1);
        GridPane.setHalignment(headerLabel, HPos.CENTER);
        GridPane.setMargin(headerLabel, new Insets(20, 0, 20, 0));

        // Add Name L abel
        Label nameLabel = new Label("Message : ");
        gridPane.add(nameLabel, 0, 1);

        // Add Name Text Field

        messField.setPrefHeight(200);
        messField.setWrapText(true);
        gridPane.add(messField, 1, 1);

        // Add Submit Button
        Button retrieveButton = new Button("Retrieve");
        retrieveButton.setPrefHeight(40);
        // retrieveButton.setDefaultButton(true);
        retrieveButton.setPrefWidth(100);
        gridPane.add(retrieveButton, 0, 4, 2, 1);
        //GridPane.setHalignment(retrieveButton, HPos.CENTER);
        GridPane.setMargin(retrieveButton, new Insets(20, 0, 20, 0));

        // Add Submit Button
        Button storeButton = new Button("Store");
        storeButton.setPrefHeight(40);
        //storeButton.setDefaultButton(true);
        storeButton.setPrefWidth(100);
        gridPane.add(storeButton, 1, 4, 2, 1);
        //GridPane.setHalignment(storeButton, HPos.CENTER);
        GridPane.setMargin(storeButton, new Insets(20, 0, 20, 0));

        storeButton.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                if (messField.getText().isEmpty()) {
                    showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "Please enter message");
                    return;
                }

                ObservableList<CharSequence> paragraph = messField.getParagraphs();
              //  try {
                    IOLocalController.storeMessage(paragraph);
              //  }

                // showAlert(Alert.AlertType.CONFIRMATION, gridPane.getScene().getWindow(), "mess saved", "mess saved");
            }
        });

        retrieveButton.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
             //   try {
                    messField.setText(IOLocalController.retrieveMessage());
              //  } //catch (IOException exc) {
                   // exc.printStackTrace();
               // }
                // showAlert(Alert.AlertType.CONFIRMATION, gridPane.getScene().getWindow(), "retrieve", "retrieved");
            }
        });
    }

    public static void showAlert(Alert.AlertType alertType, Window owner, String title, String message) {
        Alert alert = new Alert(alertType);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.initOwner(owner);
        alert.show();
    }

}
