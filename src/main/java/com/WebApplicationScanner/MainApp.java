package main.java.com.WebApplicationScanner;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class MainApp extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {
        // Load the FXML file for the main view
        Parent root = FXMLLoader.load(getClass().getResource("src/main/resources/fxml/MainView.fxml"));
        
        // Create a scene using the loaded FXML
        Scene scene = new Scene(root);
        
        // Set the title and scene for the primary stage
        primaryStage.setTitle("Web Application Vulnerability Scanner");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
