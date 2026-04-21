package com.phishingdetection.utils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Simple ARFF cleaner (writes <original>.cleaned.arff).
 */
public final class ArffCleaner {

    private ArffCleaner() {}

    public static String clean(String arffPath) throws IOException {
        Path input = Paths.get(arffPath);
        if (!Files.exists(input)) throw new FileNotFoundException("ARFF not found: " + arffPath);

        List<String> header = new ArrayList<>();
        List<String> dataLines = new ArrayList<>();
        boolean inData = false;
        int attributeCount = -1;

        try (BufferedReader br = Files.newBufferedReader(input, StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                String trimmed = line.trim();
                if (!inData) {
                    header.add(line);
                    if (trimmed.toLowerCase().startsWith("@data")) {
                        inData = true;
                        attributeCount = countAttributesFromHeader(header);
                        if (attributeCount <= 0) throw new IOException("Unable to determine attribute count.");
                    }
                } else {
                    if (trimmed.isEmpty()) continue;
                    dataLines.add(line);
                }
            }
        }

        List<String> cleaned = new ArrayList<>(dataLines.size());
        for (String raw : dataLines) cleaned.add(cleanDataLine(raw, attributeCount));

        Path cleanedPath = input.resolveSibling(input.getFileName().toString().replaceAll("\\.arff$", "") + ".cleaned.arff");
        try (BufferedWriter bw = Files.newBufferedWriter(cleanedPath, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            for (String h : header) bw.write(h + System.lineSeparator());
            if (header.stream().noneMatch(s -> s.trim().toLowerCase().startsWith("@data"))) bw.write("@data" + System.lineSeparator());
            for (String d : cleaned) bw.write(d + System.lineSeparator());
        }

        System.out.println("Debug: ARFF cleaned -> " + cleanedPath + " (cols=" + attributeCount + ", rows=" + cleaned.size() + ")");
        return cleanedPath.toString();
    }

    private static int countAttributesFromHeader(List<String> header) {
        int count = 0;
        for (String line : header) {
            String t = line.trim();
            if (t.toLowerCase().startsWith("@attribute")) count++;
            else if (t.toLowerCase().startsWith("@data")) break;
        }
        return count;
    }

    private static String cleanDataLine(String rawLine, int expectedCols) {
        String line = rawLine.trim();
        // Replace empty fields ,, -> ,?, and handle edges
        while (line.contains(",,") || line.startsWith(",") || line.endsWith(",")) {
            if (line.startsWith(",")) line = "?" + line;
            if (line.endsWith(",")) line = line + "?";
            line = line.replace(",,", ",?,");
        }
        String[] parts = line.split(",", -1);
        for (int i = 0; i < parts.length; i++) {
            if (parts[i] == null || parts[i].trim().isEmpty()) parts[i] = "?";
            else parts[i] = parts[i].trim();
        }
        if (parts.length == expectedCols) return String.join(",", parts);
        if (parts.length < expectedCols) {
            String[] pad = new String[expectedCols];
            System.arraycopy(parts, 0, pad, 0, parts.length);
            for (int i = parts.length; i < expectedCols; i++) pad[i] = "?";
            return String.join(",", pad);
        } else {
            String[] trim = new String[expectedCols];
            System.arraycopy(parts, 0, trim, 0, expectedCols);
            return String.join(",", trim);
        }
    }
}