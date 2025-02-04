package main.java.com.WebApplicationScanner.controllers;

public interface Scanner {
    /**
     * Performs a vulnerability scan on the given target URL.
     *
     * @param targetUrl The URL to scan.
     * @return A string containing the scan results.
     * @throws Exception if an error occurs during scanning.
     */
    String scan(String targetUrl) throws Exception;

    /**
     * Returns the name of the scanner (e.g., "SQL Injection Scanner").
     *
     * @return The scanner's name.
     */
    String getName();
}
