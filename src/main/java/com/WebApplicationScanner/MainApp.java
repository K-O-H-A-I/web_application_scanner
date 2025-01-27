package main.java.com.WebApplicationScanner;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class MainApp extends Application {

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        // Load the FXML file
        Parent root = FXMLLoader.load(getClass().getResource("/com/yourcompany/webscanner/MainView.fxml"));

        // Create a scene with the loaded FXML
        Scene scene = new Scene(root);

        // Apply the CSS stylesheet
        scene.getStylesheets().add(getClass().getResource("/com/yourcompany/webscanner/styles.css").toExternalForm());

        // Set the title of the application window
        primaryStage.setTitle("Web Vulnerability Scanner");

        // Set the scene for the primary stage
        primaryStage.setScene(scene);

        // Show the application window
        primaryStage.show();
    }
}
