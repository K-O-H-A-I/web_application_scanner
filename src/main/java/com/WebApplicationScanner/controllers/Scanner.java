package main.java.com.WebApplicationScanner.controllers;

public interface Scanner {
    String scan(String targetUrl) throws Exception;
    String getName();
}

