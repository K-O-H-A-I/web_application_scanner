package main.java.com.WebApplicationScanner.services;
import main.java.com.WebApplicationScanner.controllers.Scanner;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.regex.Pattern;

public class SqlInjectionScanner implements Scanner {

    // Define common SQL error patterns for various databases
    private static final Pattern[] SQL_ERROR_PATTERNS = new Pattern[]{
        Pattern.compile("SQL syntax.*MySQL", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Warning.*mysql.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("valid MySQL result", Pattern.CASE_INSENSITIVE),
        Pattern.compile("MySqlClient\\.", Pattern.CASE_INSENSITIVE),
        Pattern.compile("SQL syntax.*PostgreSQL", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Warning.*\\Wpg_.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("valid PostgreSQL result", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Npgsql\\.", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Microsoft SQL Native Client error", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Unclosed quotation mark after the character string", Pattern.CASE_INSENSITIVE),
        Pattern.compile("SQL syntax.*SQLite", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Warning.*sqlite_.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("valid SQLite result", Pattern.CASE_INSENSITIVE),
        Pattern.compile("SQLite3::", Pattern.CASE_INSENSITIVE),
        Pattern.compile("SQL syntax.*Oracle", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Warning.*\\Woci_.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile("valid Oracle result", Pattern.CASE_INSENSITIVE),
        Pattern.compile("ORA-\\d{5}", Pattern.CASE_INSENSITIVE)
    };

    // Define a list of SQL injection payloads to test against the target URL
    private static final String[] SQL_PAYLOADS = new String[]{
        "'", "\"", "';", "\";", "' OR '1'='1", "\" OR \"1\"=\"1"
    };

    /**
     * Scans the provided URL for potential SQL injection vulnerabilities.
     * It iterates through a list of SQL injection payloads, appends each payload to the URL,
     * sends an HTTP GET request, and checks the response for SQL error patterns.
     *
     * @param targetUrl The URL to be scanned.
     * @return A detailed string report indicating vulnerabilities detected or the absence thereof.
     * @throws Exception if an error occurs during scanning.
     */
    @Override
    public String scan(String targetUrl) throws Exception {
        StringBuilder resultBuilder = new StringBuilder();
        boolean vulnerabilityFound = false;

        // Iterate over each payload
        for (String payload : SQL_PAYLOADS) {
            // Construct the test URL by appending the payload appropriately
            String testUrl = targetUrl;
            if (targetUrl.contains("?")) {
                testUrl += payload;
            } else {
                testUrl += "?" + payload;
            }

            try {
                // Open an HTTP connection to the test URL
                HttpURLConnection connection = (HttpURLConnection) new URL(testUrl).openConnection();
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

                // Check if any SQL error pattern is found in the response
                for (Pattern pattern : SQL_ERROR_PATTERNS) {
                    if (pattern.matcher(response).find()) {
                        resultBuilder.append("Potential SQL Injection vulnerability detected using payload [")
                                     .append(payload)
                                     .append("] at URL: ").append(testUrl).append("\n");
                        vulnerabilityFound = true;
                        break;
                    }
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
            resultBuilder.append("No SQL Injection vulnerability detected at: ").append(targetUrl);
        }

        return resultBuilder.toString();
    }

    /**
     * Returns the name of this scanner.
     *
     * @return "SQL Injection Scanner"
     */
    @Override
    public String getName() {
        return "SQL Injection Scanner";
    }
}
