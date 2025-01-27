package main.java.com.WebApplicationScanner.controllers;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.stage.DirectoryChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

public class MainController {

    @FXML
    private TextField urlTextField;

    @FXML
    private Button submitButton;

    @FXML
    private Label statusLabel;

    private List<Scanner> scanners = List.of(
        new SqlInjectionScanner(),
        new XssScanner(),
        new CsrfScanner()
        // Add additional scanners here
    );

    @FXML
    private void initialize() {
        submitButton.setOnAction(event -> handleSubmit());
    }

    private void handleSubmit() {
        String targetUrl = urlTextField.getText().trim();
        if (targetUrl.isEmpty()) {
            statusLabel.setText("Please enter a URL.");
            return;
        }

        statusLabel.setText("Scanning in progress...");

        // Run the scans in a separate thread to avoid blocking the UI
        new Thread(() -> {
            StringBuilder reportBuilder = new StringBuilder();
            for (Scanner scanner : scanners) {
                try {
                    String result = scanner.scan(targetUrl);
                    reportBuilder.append(result).append("\n");
                } catch (Exception e) {
                    reportBuilder.append("Error during ").append(scanner.getName())
                                 .append(" scan: ").append(e.getMessage()).append("\n");
                }
            }

            String reportContent = reportBuilder.toString();

            // Update the UI and prompt for download directory on the JavaFX Application Thread
            Platform.runLater(() -> {
                statusLabel.setText("Scanning completed. Please choose a directory to save the report.");
                promptForDownloadDirectory(reportContent);
            });
        }).start();
    }

    private void promptForDownloadDirectory(String reportContent) {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Select Download Directory");

        // Set the initial directory to the 'reports' folder in your project
        File reportsDirectory = new File("web_application_scanner/reports");
        if (reportsDirectory.exists() && reportsDirectory.isDirectory()) {
            directoryChooser.setInitialDirectory(reportsDirectory);
        } else {
            // If the 'reports' folder doesn't exist, set the initial directory to the user's home directory
            directoryChooser.setInitialDirectory(new File(System.getProperty("user.home")));
        }

        File selectedDirectory = directoryChooser.showDialog(new Stage());

        if (selectedDirectory != null) {
            File reportFile = new File(selectedDirectory, "scan_report.txt");
            try (OutputStream out = new FileOutputStream(reportFile)) {
                out.write(reportContent.getBytes());
                statusLabel.setText("Report saved successfully.");
            } catch (IOException e) {
                statusLabel.setText("Failed to save the report.");
                e.printStackTrace();
            }
        } else {
            statusLabel.setText("No directory selected. Report not saved.");
        }
    }
}
