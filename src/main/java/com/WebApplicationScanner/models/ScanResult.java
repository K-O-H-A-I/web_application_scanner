package main.java.com.WebApplicationScanner.models;

import java.util.HashMap;
import java.util.Map;

/**
 * ScanResult represents the result of a vulnerability scan on a target URL.
 * It stores the scan outcomes for various vulnerability types along with
 * relevant details such as detection status and severity.
 */
public class ScanResult {
    
    private String url;
    // A map storing vulnerability type as key and its details as value
    private Map<String, Vulnerability> vulnerabilities;

    /**
     * Constructs a ScanResult for the specified URL.
     *
     * @param url the target URL that was scanned
     */
    public ScanResult(String url) {
        this.url = url;
        this.vulnerabilities = new HashMap<>();
    }

    /**
     * Adds or updates the result of a vulnerability scan.
     *
     * @param type      The type of vulnerability (e.g., "SQL Injection")
     * @param detected  True if the vulnerability was detected, false otherwise
     * @param severity  The severity level (e.g., 1-10) if detected; otherwise 0
     */
    public void addVulnerability(String type, boolean detected, int severity) {
        vulnerabilities.put(type, new Vulnerability(detected, severity));
    }

    /**
     * Generates a detailed textual report summarizing the scan results.
     *
     * @return A formatted string report of all vulnerability findings.
     */
    public String generateReport() {
        StringBuilder reportBuilder = new StringBuilder();
        reportBuilder.append("Scan Report for: ").append(url).append("\n\n");
        for (Map.Entry<String, Vulnerability> entry : vulnerabilities.entrySet()) {
            String type = entry.getKey();
            Vulnerability vuln = entry.getValue();
            reportBuilder.append("Vulnerability: ").append(type).append("\n")
                         .append("Status: ").append(vuln.isDetected() ? "Detected" : "Not Detected").append("\n");
            if (vuln.isDetected()) {
                reportBuilder.append("Severity: ").append(vuln.getSeverity()).append("\n");
            }
            reportBuilder.append("\n");
        }
        return reportBuilder.toString();
    }

    /**
     * Inner class representing details of a particular vulnerability.
     */
    private static class Vulnerability {
        private boolean detected;
        private int severity;

        /**
         * Constructs a Vulnerability with the specified status and severity.
         *
         * @param detected True if the vulnerability is detected
         * @param severity Severity level (e.g., 1-10)
         */
        public Vulnerability(boolean detected, int severity) {
            this.detected = detected;
            this.severity = severity;
        }

        public boolean isDetected() {
            return detected;
        }

        public int getSeverity() {
            return severity;
        }
    }
}

