package com.phishingdetection.rest;

import com.phishingdetection.ml.EnsembleWekaClassifier;
import static spark.Spark.*;
import com.google.gson.Gson;

/**
 * Simple Spark Java server.
 * - GET /api/check?url=<url> -> JSON result
 * - GET /health -> "OK"
 */
public class Server {

    private static EnsembleWekaClassifier ensemble;

    public static void main(String[] args) {
        System.out.println("Debug: Starting server...");

        try {
            System.out.println("Debug: Initializing ensemble classifier...");
            ensemble = new EnsembleWekaClassifier("dataset/Training_Dataset.arff");
            System.out.println("Debug: Ensemble classifier initialized successfully.");
        } catch (Exception e) {
            System.err.println("Debug: Failed to initialize classifier.");
            e.printStackTrace();
            System.exit(1);
        }

        // choose port (change if 4567 is in use)
        port(4567);
        staticFiles.location("/public"); // optional

        get("/", (req, res) -> {
            res.redirect("/index.html");
            return null;
        });

        get("/api/check", (req, res) -> {
            String url = req.queryParams("url");
            res.type("application/json");
            if (url == null || url.trim().isEmpty()) {
                res.status(400);
                return new ApiResponse("error", "Please provide a url parameter.");
            }

            try {
                System.out.println("Debug: Classifying URL: " + url);
                boolean phishing = ensemble.classifyUrl(url);
                return new ApiResponse("success", phishing ? "Phishing URL detected" : "Legitimate URL");
            } catch (Exception e) {
                e.printStackTrace();
                res.status(500);
                return new ApiResponse("error", "Internal server error during classification.");
            }
        }, new Gson()::toJson);

        get("/health", (req, res) -> "OK");

        System.out.println("Debug: Server running at http://localhost:4567");
    }

    // simple response object for Gson
    private static class ApiResponse {
        private final String status;
        private final String message;

        ApiResponse(String status, String message) {
            this.status = status;
            this.message = message;
        }

        // getters used by Gson
        @SuppressWarnings("unused")
        public String getStatus() { return status; }

        @SuppressWarnings("unused")
        public String getMessage() { return message; }
    }
}