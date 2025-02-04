package main.java.com.WebApplicationScanner.services;
import main.java.com.WebApplicationScanner.controllers.Scanner;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class CsrfScanner implements Scanner {

    /**
     * Scans the provided URL for potential CSRF vulnerabilities.
     * This basic implementation checks if the response HTML contains common CSRF token identifiers.
     *
     * @param targetUrl The URL to be scanned.
     * @return A string report indicating whether CSRF protection appears to be implemented.
     * @throws Exception if an error occurs during the scanning process.
     */
    @Override
    public String scan(String targetUrl) throws Exception {
        StringBuilder resultBuilder = new StringBuilder();
        
        // Open an HTTP connection to the target URL
        HttpURLConnection connection = (HttpURLConnection) new URL(targetUrl).openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        
        // Read the response from the server
        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        StringBuilder responseBuilder = new StringBuilder();
        String line;
        while ((line = in.readLine()) != null) {
            responseBuilder.append(line);
        }
        in.close();
        
        String response = responseBuilder.toString();
        
        // Basic check: look for common anti-CSRF token identifiers in the HTML form
        if (response.contains("name=\"csrf_token\"") || response.contains("name=\"_csrf\"")) {
            resultBuilder.append("CSRF protection appears to be implemented at: ").append(targetUrl);
        } else {
            resultBuilder.append("Potential CSRF vulnerability detected at: ").append(targetUrl);
        }
        
        return resultBuilder.toString();
    }

    /**
     * Returns the name of this scanner.
     *
     * @return "CSRF Scanner"
     */
    @Override
    public String getName() {
        return "CSRF Scanner";
    }
}
