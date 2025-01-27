package main.java.com.WebApplicationScanner.services;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.regex.Pattern;


public class SqlInjectionScanner {

    // Common SQL error patterns to detect potential vulnerabilities
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

    // Common SQL injection payloads
    private static final String[] SQL_PAYLOADS = new String[]{
        "'", "\"", "''", "';", "\";", "' OR '1'='1", "\" OR \"1\"=\"1",
        "' OR '1'='1' --", "\" OR \"1\"=\"1\" --", "' OR '1'='1' /*", "\" OR \"1\"=\"1\" /*"
    };

    /**
     * Scans the provided URL for potential SQL injection vulnerabilities.
     *
     * @param url The URL to scan.
     * @return true if a potential SQL injection vulnerability is detected; false otherwise.
     */
    public boolean scanForSqlInjection(String url) {
        // Extract the base URL and parameters
        String baseUrl = url.split("\\?")[0];
        String[] params = url.contains("?") ? url.split("\\?")[1].split("&") : new String[]{};

        // Iterate over each parameter and test with SQL payloads
        for (String param : params) {
            String paramName = param.split("=")[0];
            for (String payload : SQL_PAYLOADS) {
                String testUrl = constructTestUrl(baseUrl, params, paramName, payload);
                if (sendRequestAndCheckVulnerability(testUrl)) {
                    return true; // Vulnerability detected
                }
            }
        }
        return false; // No vulnerabilities detected
    }

    /**
     * Constructs a test URL by injecting the payload into the specified parameter.
     *
     * @param baseUrl   The base URL without parameters.
     * @param params    The original parameters.
     * @param paramName The name of the parameter to inject.
     * @param payload   The SQL injection payload.
     * @return The constructed test URL with the payload injected.
     */
    private String constructTestUrl(String baseUrl, String[] params, String paramName, String payload) {
        StringBuilder testUrl = new StringBuilder(baseUrl + "?");
        for (String param : params) {
            String name = param.split("=")[0];
            String value = param.split("=").length > 1 ? param.split("=")[1] : "";
            if (name.equals(paramName)) {
                value += payload; // Inject payload
            }
            testUrl.append(name).append("=").append(value).append("&");
        }
        return testUrl.toString().replaceAll("&$", ""); // Remove trailing '&'
    }

    /**
     * Sends an HTTP GET request to the specified URL and checks for SQL error patterns in the response.
     *
     * @param testUrl The URL to test.
     * @return true if a potential SQL injection vulnerability is detected; false otherwise.
     */
    private boolean sendRequestAndCheckVulnerability(String testUrl) {
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(testUrl).openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder response = new StringBuilder();
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            String responseContent = response.toString();
            for (Pattern pattern : SQL_ERROR_PATTERNS) {
                if (pattern.matcher(responseContent).find()) {
                    return true; // SQL error pattern found
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false; // No SQL error patterns detected
    }
}
