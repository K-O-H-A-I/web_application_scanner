package main.java.com.WebApplicationScanner.services;
import main.java.com.WebApplicationScanner.controllers.Scanner;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.regex.Pattern;

public class XssScanner implements Scanner {

    // Define common XSS payloads to test against the target URL
    private static final String[] XSS_PAYLOADS = new String[]{
        "<script>alert('XSS')</script>",
        "\"><script>alert(1)</script>",
        "'><script>alert('XSS')</script>"
    };

    // Optionally, you can define a pattern to search for the payload in the response
    private static final Pattern XSS_PATTERN = Pattern.compile("<script>alert\\((?:'XSS'|1)\\)</script>", Pattern.CASE_INSENSITIVE);

    /**
     * Scans the provided URL for potential XSS vulnerabilities.
     * It appends various XSS payloads to the URL (assuming vulnerable parameters) and checks if the payload is reflected in the response.
     *
     * @param targetUrl The URL to be scanned.
     * @return A detailed string report indicating vulnerabilities detected or their absence.
     * @throws Exception if an error occurs during scanning.
     */
    @Override
    public String scan(String targetUrl) throws Exception {
        StringBuilder resultBuilder = new StringBuilder();
        boolean vulnerabilityFound = false;

        // Iterate over each XSS payload
        for (String payload : XSS_PAYLOADS) {
            // Construct the test URL by appending the payload appropriately.
            // If the URL already contains parameters, append the payload to the first parameter.
            String testUrl;
            if (targetUrl.contains("?")) {
                testUrl = targetUrl + payload;
            } else {
                testUrl = targetUrl + "?" + payload;
            }

            try {
                // Open HTTP connection to the test URL
                HttpURLConnection connection = (HttpURLConnection) new URL(testUrl).openConnection();
                connection.setRequestMethod("GET");
                connection.setConnectTimeout(5000);
                connection.setReadTimeout(5000);

                // Read the response content
                BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder responseBuilder = new StringBuilder();
                String line;
                while ((line = in.readLine()) != null) {
                    responseBuilder.append(line);
                }
                in.close();

                String response = responseBuilder.toString();

                // Check if the XSS payload is reflected in the response
                if (response.contains(payload) || XSS_PATTERN.matcher(response).find()) {
                    resultBuilder.append("Potential XSS vulnerability detected using payload [")
                                 .append(payload)
                                 .append("] at URL: ").append(testUrl).append("\n");
                    vulnerabilityFound = true;
                }
            } catch (Exception e) {
                // Log error for the specific payload attempt and continue testing
                resultBuilder.append("Error testing payload [").append(payload)
                             .append("] at URL: ").append(testUrl)
                             .append(" - ").append(e.getMessage()).append("\n");
            }
        }

        // If no vulnerabilities were detected, report accordingly
        if (!vulnerabilityFound) {
            resultBuilder.append("No XSS vulnerability detected at: ").append(targetUrl);
        }

        return resultBuilder.toString();
    }

    /**
     * Returns the name of this scanner.
     *
     * @return "XSS Scanner"
     */
    @Override
    public String getName() {
        return "XSS Scanner";
    }
}
