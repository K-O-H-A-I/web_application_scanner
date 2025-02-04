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
import java.util.logging.Logger;
import java.util.logging.FileHandler;
import java.util.logging.SimpleFormatter;

public class MainController {

    @FXML
    private TextField urlTextField;

    @FXML
    private Button submitButton;

    @FXML
    private Label statusLabel;

    // List of all vulnerability scanners (each implementing our custom Scanner interface)
    private List<Scanner> scanners = List.of(
            new SqlInjectionScanner(),
            new XssScanner(),
            new CsrfScanner()
            // Additional scanners can be added here
    );

    // Set up a logger to record runtime information and errors into the logs folder
    private static final Logger logger = Logger.getLogger(MainController.class.getName());

    static {
        try {
            FileHandler fh = new FileHandler("web_application_scanner/logs/app.log", true);
            fh.setFormatter(new SimpleFormatter());
            logger.addHandler(fh);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @FXML
    private void initialize() {
        // Set action for the submit button
        submitButton.setOnAction(event -> handleSubmit());
    }

    private void handleSubmit() {
        String targetUrl = urlTextField.getText().trim();
        if (targetUrl.isEmpty()) {
            statusLabel.setText("Please enter a URL.");
            logger.warning("No URL provided by the user.");
            return;
        }

        statusLabel.setText("Scanning in progress...");
        logger.info("Starting scan for URL: " + targetUrl);

        // Run scans in a separate thread to keep the UI responsive
        new Thread(() -> {
            StringBuilder reportBuilder = new StringBuilder();
            for (Scanner scanner : scanners) {
                try {
                    logger.info("Running scanner: " + scanner.getName());
                    String result = scanner.scan(targetUrl);
                    reportBuilder.append(result).append("\n");
                } catch (Exception e) {
                    String errorMsg = "Error during " + scanner.getName() + " scan: " + e.getMessage();
                    reportBuilder.append(errorMsg).append("\n");
                    logger.severe(errorMsg);
                }
            }
            String reportContent = reportBuilder.toString();
            logger.info("Scanning complete. Report generated.");

            // Update the UI after scanning is complete and prompt for directory selection
            Platform.runLater(() -> {
                statusLabel.setText("Scanning completed. Please choose a directory to save the report.");
                promptForDownloadDirectory(reportContent);
            });
        }).start();
    }

    private void promptForDownloadDirectory(String reportContent) {
        DirectoryChooser directoryChooser = new DirectoryChooser();
        directoryChooser.setTitle("Select Download Directory");

        // Set the initial directory to the project's "web_application_scanner/reports" folder
        File reportsDirectory = new File("web_application_scanner/reports");
        if (reportsDirectory.exists() && reportsDirectory.isDirectory()) {
            directoryChooser.setInitialDirectory(reportsDirectory);
        } else {
            // Fallback to user's home directory if the reports folder doesn't exist
            directoryChooser.setInitialDirectory(new File(System.getProperty("user.home")));
        }

        File selectedDirectory = directoryChooser.showDialog(new Stage());
        if (selectedDirectory != null) {
            File reportFile = new File(selectedDirectory, "scan_report.txt");
            try (OutputStream out = new FileOutputStream(reportFile)) {
                out.write(reportContent.getBytes());
                statusLabel.setText("Report saved successfully.");
                logger.info("Report saved to: " + reportFile.getAbsolutePath());
            } catch (IOException e) {
                statusLabel.setText("Failed to save the report.");
                logger.severe("Failed to save report: " + e.getMessage());
            }
        } else {
            statusLabel.setText("No directory selected. Report not saved.");
            logger.warning("User cancelled directory selection.");
        }
    }
}
