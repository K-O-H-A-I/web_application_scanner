package main.java.com.WebApplicationScanner.models;

import java.util.HashMap;
import java.util.Map;

public class ScanResult {
    private String url;
    private Map<String, Vulnerability> vulnerabilities = new HashMap<>();

    public ScanResult(String url) {
        this.url = url;
    }

    public ScanResult(String url, boolean sqlInjectionDetected, int sqlInjectionSeverity, boolean xssDetected, int xssSeverity) {
        this.url = url;
        this.vulnerabilities.put("SQL Injection", new Vulnerability(sqlInjectionDetected, sqlInjectionSeverity));
        this.vulnerabilities.put("XSS", new Vulnerability(xssDetected, xssSeverity));
    }

    public String getUrl() {
        return url;
    }

    public void addVulnerability(String type, boolean detected, int severity) {
        this.vulnerabilities.put(type, new Vulnerability(detected, severity));
    }

    public Map<String, Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public String generateReport() {
        StringBuilder reportBuilder = new StringBuilder();
        reportBuilder.append("Scan Report for: ").append(url).append("\n");

        for (Map.Entry<String, Vulnerability> entry : vulnerabilities.entrySet()) {
            String type = entry.getKey();
            Vulnerability vuln = entry.getValue();
            reportBuilder.append(type).append(": ").append(vuln.isDetected() ? "Yes" : "No").append("\n");
            if (vuln.isDetected()) {
                reportBuilder.append("Severity: ").append(vuln.getSeverity()).append("\n");
            }
        }

        return reportBuilder.toString();
    }

    private static class Vulnerability {
        private boolean detected;
        private int severity;

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
