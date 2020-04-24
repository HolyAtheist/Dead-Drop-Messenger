package deaddrop_prototype;

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

import java.util.Date;
import java.util.Objects;

public class View {
    private static GridPane gridPane;
    private static TextArea messField = new TextArea();
    private static TextField nameField = new TextField();
    private static PasswordField passwordField = new PasswordField();

    private static Controller controller;
    private static IOLocalController ioLocalController;
    private static IODeadDropController ioDeadDropController;

    private static TextField protocolField = new TextField();
    private static TextField baseUrlField = new TextField();
    private static TextField idUrlField = new TextField();
    private static TextField idHeaderField = new TextField();

    private Model model;

    public View(Controller controller1, IOLocalController controller2, IODeadDropController controller3, Model model) {

        //// note: some of the View class is based on the example from https://www.callicoder.com/javafx-registration-form-gui-tutorial/

        this.controller = controller1;
        this.ioLocalController = controller2;
        this.ioDeadDropController = controller3;
        this.model = model;

        GridPane gridPane = createDefaultFormPane();

        loginSceneElements(gridPane);
    }

    public Parent asParent() {
        return gridPane;
    }

    //// setup various defaults
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
        ColumnConstraints columnTwoConstrains = new ColumnConstraints(100, 100, Double.MAX_VALUE);
        columnTwoConstrains.setHgrow(Priority.ALWAYS);

        gridPane.getColumnConstraints().addAll(columnOneConstraints, columnTwoConstrains);

        return gridPane;
    }

    //// the login view
    public static void loginSceneElements(GridPane gridPane) {

        // Add TEST1 Button
        Button testOneButton = new Button("TEST1");
        testOneButton.setPrefHeight(20);
        testOneButton.setPrefWidth(60);
        gridPane.add(testOneButton, 0, 0, 1, 1);
        GridPane.setMargin(testOneButton, new Insets(20, 0, 20, 0));

        // Add TEST1 Button
        Button testTwoButton = new Button("TEST2");
        testTwoButton.setPrefHeight(20);
        testTwoButton.setPrefWidth(60);
        gridPane.add(testTwoButton, 1, 0, 1, 1);
        GridPane.setMargin(testTwoButton, new Insets(20, 0, 20, 0));


        // Add Header
        Label headerLabel = new Label("Login or Create new account");
        headerLabel.setFont(Font.font("Arial", FontWeight.BOLD, 24));
        gridPane.add(headerLabel, 1, 1, 2, 1);
        GridPane.setHalignment(headerLabel, HPos.CENTER);
        GridPane.setMargin(headerLabel, new Insets(20, 0, 20, 0));

        // Add Name Label
        Label nameLabel = new Label("Name : ");
        gridPane.add(nameLabel, 0, 2);

        // Add Name Text Field
        nameField.setPrefHeight(40);
        gridPane.add(nameField, 1, 2);
        nameField.textProperty().addListener((obs, oldText, newText) -> controller.updateName(newText));

        // Add Password Label
        Label passwordLabel = new Label("Password : ");
        gridPane.add(passwordLabel, 0, 4);

        // Add Password Field
        passwordField.setPrefHeight(40);
        gridPane.add(passwordField, 1, 4);
        passwordField.textProperty().addListener((obs, oldText, newText) -> controller.updatePass(newText));

        // Add login Button
        Button loginButton = new Button("Login");
        loginButton.setPrefHeight(40);
        //loginButton.setDefaultButton(true);
        loginButton.setPrefWidth(100);
        gridPane.add(loginButton, 1, 5, 2, 1);
        GridPane.setMargin(loginButton, new Insets(20, 0, 20, 0));

        // Add new account Button
        Button createNewAccountButton = new Button("Create New");
        createNewAccountButton.setPrefHeight(40);
        createNewAccountButton.setPrefWidth(100);
        gridPane.add(createNewAccountButton, 0, 5, 2, 1);
        GridPane.setMargin(createNewAccountButton, new Insets(20, 0, 20, 0));


        testOneButton.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                //test 1 'script'
                //
                System.out.println("Test 1 selected..");

                nameField.textProperty().setValue("testname");
                passwordField.textProperty().setValue("testpassword");

                System.out.println("Inputting name -- " + nameField.getText());
                System.out.println("Inputting password -- " + passwordField.getText());

                System.out.println("Trying to create account..");
                // then go to next scene
                ioLocalController.storeAccount();

                System.out.println("Going to message view...");

                gridPane.getChildren().clear();
                messageSceneElements(gridPane);
                System.out.println("Creating account hopefully succeeded.");

                System.out.println("Going to config view...");

                //goto config
                gridPane.getChildren().clear();
                configSceneElements(gridPane);

                //input config
                protocolField.setText("https://");
                baseUrlField.setText("jsonblob.com/api/jsonBlob/");
                idHeaderField.setText("X-jsonblob");

                System.out.println("Filling protocol field with -- " + controller.getProtocol());
                System.out.println("Filling base url field with -- " + controller.getBaseUrl());
                System.out.println("Filling id header field with -- " + controller.getIdHeader());

                // get new id
                if (ioDeadDropController.getNewId()) {
                    System.out.println("Got new id/dead drop url -- " + controller.getIdUrl());
                    //save config
                    ioLocalController.storeConfig();
                    System.out.println("Configuration hopefully saved.");
                    // go back to message view
                    System.out.println("Going back to message view...");
                    gridPane.getChildren().clear();
                    messageSceneElements(gridPane);
                    System.out.printf("Setting new message: ");

                    Date date1 = new Date();
                    String newTest1Message = "Message by TEST ONE -- " + date1;
                    messField.setText(newTest1Message);
                    System.out.println(newTest1Message);
                    // put new message

                    System.out.println("Trying to store new message in dead drop..");
                    ioDeadDropController.storeMessageDeadDrop();

                    if (Objects.equals(controller.getStatus(), "Message seems to have been stored ok!")) {
                        // verify message
                        System.out.println("Message was stored remotely!");
                    }
                    System.out.println("Test 1 appears to have succeeded!");

                } else System.out.println("Could not get new id/dead drop :(");


            }
        });

        testTwoButton.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                //test 2 'script'
                //
                System.out.println("Test 2 selected..");
                System.out.println("Inputting name..");
                nameField.textProperty().setValue("testname");
                System.out.println("Inputting password..");
                passwordField.textProperty().setValue("testpassword");

                System.out.println("Trying to log in..");
                //if found matching account login/password then go to next scene
                if (ioLocalController.retrieveAccount()) {

                    ioLocalController.retrieveConfig();
                    gridPane.getChildren().clear();
                    messageSceneElements(gridPane);
                    System.out.println("Login succeeded.");

                    //retrieve message from deaddrop
                    System.out.println("Trying to retrieve encrypted message from remote dead drop...");

                    ioDeadDropController.retrieveMessageDeadDrop();
                    messField.setText(controller.getMess());
                    if (Objects.equals(controller.getStatus(), "Message seems to have been retrieved ok!")) {
                        System.out.println("Message was retrieved!");
                        System.out.println("Retrieved message content: " + controller.getMess());

                        System.out.printf("Setting new message: ");

                        Date date = new Date();
                        String newTestMessage = "Message by TEST2 -- " + date;
                        messField.setText(newTestMessage);
                        System.out.println(newTestMessage);
                        // put new message

                        System.out.println("Trying to store new message in dead drop..");
                        ioDeadDropController.storeMessageDeadDrop();

                        if (Objects.equals(controller.getStatus(), "Message seems to have been stored ok!")) {
                            // verify message
                            System.out.println("Message was stored remotely!");
                            System.out.println("Verifying stored message..");

                            ioDeadDropController.retrieveMessageDeadDrop();
                            if (Objects.equals(controller.getStatus(), "Message seems to have been retrieved ok!")) {
                                if (Objects.equals(controller.getMess(), newTestMessage)) {
                                    System.out.println("Message verified!");
                                    System.out.println("Test 2 is complete.");
                                } else System.out.println("Message could not be verified :(");
                            }

                        } else System.out.println("Could not store message in dead drop :(");

                    } else System.out.println("Could not retrieve message from dead drop :(");

                } else System.out.println("Login failed for some reason.. Are account files in default path?");

            }
        });


        createNewAccountButton.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                //todo: check password quality
                if (nameField.getText().isEmpty()) {
                    showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "Please enter your name");
                    return;
                }
                if (passwordField.getText().isEmpty()) {
                    showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "Please enter a password");
                    return;
                }

                //call storeAccount and go to next scene
                //todo: storeAccount() should return true if successfully created .acc files
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

                //if found matching account login/password then go to next scene
                if (ioLocalController.retrieveAccount()) {
                    //showAlert(Alert.AlertType.CONFIRMATION, gridPane.getScene().getWindow(), "Login", "Welcome " + nameField.getText());
                    ioLocalController.retrieveConfig();
                    gridPane.getChildren().clear();
                    messageSceneElements(gridPane);
                }
            }
        });
    }

    //// the main message view, where user can store, retrieve, go to configure
    public static void messageSceneElements(GridPane gridPane) {
        // Add Header
        Label headerLabel = new Label("Message");
        headerLabel.setFont(Font.font("Arial", FontWeight.BOLD, 24));
        gridPane.add(headerLabel, 0, 0, 2, 1);
        GridPane.setHalignment(headerLabel, HPos.CENTER);
        GridPane.setMargin(headerLabel, new Insets(20, 0, 20, 0));

        // Add message Label
        Label nameLabel = new Label("Message : ");
        gridPane.add(nameLabel, 0, 1);

        // Add status Label
        Label statusLabel = new Label("Status : ");
        gridPane.add(statusLabel, 0, 6);
        Label statusLabel2 = new Label("");
        gridPane.add(statusLabel2, 1, 6);

        // Add message Text Field
        messField.setPrefHeight(200);
        messField.setWrapText(true);
        gridPane.add(messField, 1, 1);
        messField.textProperty().addListener((obs, oldText, newText) -> controller.updateMess(newText));

        // Add retrieve Button
        Button retrieveButton = new Button("Retrieve locally");
        retrieveButton.setPrefHeight(40);
        retrieveButton.setPrefWidth(100);
        gridPane.add(retrieveButton, 0, 4, 2, 1);
        GridPane.setMargin(retrieveButton, new Insets(20, 0, 20, 0));

        // Add retrieve dead drop Button
        Button retrieveDeadDropButton = new Button("Retrieve from dead drop");
        retrieveDeadDropButton.setPrefHeight(40);
        retrieveDeadDropButton.setPrefWidth(150);
        gridPane.add(retrieveDeadDropButton, 0, 5, 2, 1);
        GridPane.setMargin(retrieveDeadDropButton, new Insets(20, 0, 20, 0));

        // Add store Button
        Button storeButton = new Button("Store locally");
        storeButton.setPrefHeight(40);
        storeButton.setPrefWidth(100);
        gridPane.add(storeButton, 1, 4, 2, 1);
        GridPane.setMargin(storeButton, new Insets(20, 0, 20, 0));

        // Add store dead drop Button
        Button storeDeadDropButton = new Button("Store in dead drop");
        storeDeadDropButton.setPrefHeight(40);
        storeDeadDropButton.setPrefWidth(150);
        gridPane.add(storeDeadDropButton, 1, 5, 2, 1);
        GridPane.setMargin(storeDeadDropButton, new Insets(20, 0, 20, 0));

        // Add config Button
        Button gotoConfigButton = new Button("Config");
        gotoConfigButton.setPrefHeight(40);
        gotoConfigButton.setPrefWidth(70);
        gridPane.add(gotoConfigButton, 6, 6, 1, 1);
        GridPane.setMargin(gotoConfigButton, new Insets(20, 0, 20, 0));

        gotoConfigButton.setOnAction(new EventHandler<ActionEvent>() {  // 'config' button action
            @Override
            public void handle(ActionEvent event) {
                gridPane.getChildren().clear();
                configSceneElements(gridPane);
            }
        });

        storeButton.setOnAction(new EventHandler<ActionEvent>() {   // encrypt & store message locally
            @Override
            public void handle(ActionEvent event) {
                if (messField.getText().isEmpty()) {
                    showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "Please enter message");
                    return;
                }
                //call encrypt and save message
                ioLocalController.storeMessage();
                // showAlert(Alert.AlertType.CONFIRMATION, gridPane.getScene().getWindow(), "mess saved", "mess saved");
            }
        });

        storeDeadDropButton.setOnAction(new EventHandler<ActionEvent>() {   // encrypt & store message in remote deaddrop
            @Override
            public void handle(ActionEvent event) {
                if (messField.getText().isEmpty()) {
                    showAlert(Alert.AlertType.ERROR, gridPane.getScene().getWindow(), "Form Error!", "Please enter message");
                    return;
                }
                //call encrypt and save message
                ioDeadDropController.storeMessageDeadDrop();
                statusLabel2.setText(controller.getStatus());   //set the status label
                // showAlert(Alert.AlertType.CONFIRMATION, gridPane.getScene().getWindow(), "mess saved", "mess saved");
            }
        });

        retrieveButton.setOnAction(new EventHandler<ActionEvent>() {    // retrieve & decrypt message locally
            @Override
            public void handle(ActionEvent event) {
                //call retrieve and decrypt message
                messField.setText(IOLocalController.retrieveMessage());
                // showAlert(Alert.AlertType.CONFIRMATION, gridPane.getScene().getWindow(), "retrieve", "retrieved");
            }
        });

        retrieveDeadDropButton.setOnAction(new EventHandler<ActionEvent>() {    // retrieve & decrypt message from deaddrop
            @Override
            public void handle(ActionEvent event) {
                //call retrieve and decrypt message
                ioDeadDropController.retrieveMessageDeadDrop();
                messField.setText(controller.getMess());
                statusLabel2.setText(controller.getStatus());   //set the status label
                // showAlert(Alert.AlertType.CONFIRMATION, gridPane.getScene().getWindow(), "retrieve", "retrieved");
            }
        });

    }

    //// the configuration view
    public static void configSceneElements(GridPane gridPane) {
        // Add Header
        Label headerLabel = new Label("Dead Drop Configuration");
        headerLabel.setFont(Font.font("Arial", FontWeight.BOLD, 24));
        gridPane.add(headerLabel, 0, 0, 2, 1);
        GridPane.setHalignment(headerLabel, HPos.CENTER);
        GridPane.setMargin(headerLabel, new Insets(20, 0, 20, 0));

        // Add protocol Label and field
        Label protocolLabel = new Label("Protocol : ");
        gridPane.add(protocolLabel, 0, 1);
        protocolField.setPrefHeight(40);
        gridPane.add(protocolField, 1, 1);
        protocolField.setText(controller.getProtocol());
        protocolField.textProperty().addListener((obs, oldText, newText) -> controller.updateProtocol(newText));

        // Add base url Label and field
        Label baseUrlLabel = new Label("Base URL : ");
        gridPane.add(baseUrlLabel, 0, 2);
        baseUrlField.setPrefHeight(40);
        gridPane.add(baseUrlField, 1, 2);
        baseUrlField.setText(controller.getBaseUrl());
        baseUrlField.textProperty().addListener((obs, oldText, newText) -> controller.updateBaseUrl(newText));

        // Add id url Label and field
        Label idUrlLabel = new Label("ID URL : ");
        gridPane.add(idUrlLabel, 0, 3);
        idUrlField.setPrefHeight(40);
        gridPane.add(idUrlField, 1, 3);
        idUrlField.setText(controller.getIdUrl());
        idUrlField.textProperty().addListener((obs, oldText, newText) -> controller.updateIdUrl(newText));

        // Add id header Label and field
        Label idHeaderLabel = new Label("ID Header : ");
        gridPane.add(idHeaderLabel, 2, 3);
        idHeaderField.setPrefHeight(40);
        gridPane.add(idHeaderField, 3, 3);
        idHeaderField.setText(controller.getIdHeader());
        idHeaderField.textProperty().addListener((obs, oldText, newText) -> controller.updateIdHeader(newText));

        // Add get new id Button
        Button getNewIdButton = new Button("Get New ID");
        getNewIdButton.setPrefHeight(40);
        getNewIdButton.setPrefWidth(80);
        gridPane.add(getNewIdButton, 6, 3, 1, 1);
        GridPane.setMargin(getNewIdButton, new Insets(20, 0, 20, 0));

        // Add exit config Button
        Button gotoMessageViewButton = new Button("Back");
        gotoMessageViewButton.setPrefHeight(40);
        gotoMessageViewButton.setPrefWidth(70);
        gridPane.add(gotoMessageViewButton, 6, 6, 1, 1);
        GridPane.setMargin(gotoMessageViewButton, new Insets(20, 0, 20, 0));

        // Add save config Button
        Button saveConfigButton = new Button("Save Config");
        saveConfigButton.setPrefHeight(40);
        saveConfigButton.setPrefWidth(100);
        gridPane.add(saveConfigButton, 1, 6, 1, 1);
        GridPane.setMargin(saveConfigButton, new Insets(20, 0, 20, 0));


        gotoMessageViewButton.setOnAction(new EventHandler<ActionEvent>() {  // change view back to message view
            @Override
            public void handle(ActionEvent event) {
                gridPane.getChildren().clear();
                messageSceneElements(gridPane);
            }
        });
        getNewIdButton.setOnAction(new EventHandler<ActionEvent>() { // get new id button action
            @Override
            public void handle(ActionEvent event) {
                if (ioDeadDropController.getNewId()) {    // getNewId() tries to get a new id -- a new deaddrop -- for the configured site
                    idUrlField.setText(controller.getIdUrl());
                }
            }
        });
        saveConfigButton.setOnAction(new EventHandler<ActionEvent>() { // save config button action
            @Override
            public void handle(ActionEvent event) {
                ioLocalController.storeConfig();
            }
        });

    }

    //// alert popup method
    //// note: based on the example from https://www.callicoder.com/javafx-registration-form-gui-tutorial/
    public static void showAlert(Alert.AlertType alertType, Window owner, String title, String message) {
        Alert alert = new Alert(alertType);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.initOwner(owner);
        alert.show();
    }

}
