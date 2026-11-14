// =============================================================================
// WARNING: THIS FILE CONTAINS INTENTIONAL VULNERABILITIES FOR SECURITY RESEARCH.
// DO NOT DEPLOY IN PRODUCTION.
// =============================================================================
package com.secureheal.target.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class SystemController {

    private static final String UPLOADS_DIR = "/app/uploads";

    // -----------------------------------------------------------------------
    // POST /api/system/execute — VULNERABLE: CWE-78 (OS Command Injection)
    // -----------------------------------------------------------------------
    @PostMapping("/system/execute")
    public ResponseEntity<?> executeCommand(@RequestBody Map<String, String> body) {
        String hostname = body.getOrDefault("hostname", "");
        try {
            // VULNERABLE: CWE-78 — User input passed directly to Runtime.exec with shell
            Process process = Runtime.getRuntime().exec("ping -c 1 " + hostname);
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();
            return ResponseEntity.ok(Map.of(
                    "command", "ping -c 1 " + hostname,
                    "output", output.toString(),
                    "exitCode", process.exitValue()
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    // -----------------------------------------------------------------------
    // POST /api/proxy/fetch — VULNERABLE: CWE-918 (SSRF)
    // -----------------------------------------------------------------------
    @PostMapping("/proxy/fetch")
    public ResponseEntity<?> proxyFetch(@RequestBody Map<String, String> body) {
        String targetUrl = body.getOrDefault("url", "");
        try {
            // VULNERABLE: CWE-918 — No URL validation; internal resources reachable
            URL url = new URL(targetUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            reader.close();

            return ResponseEntity.ok(Map.of(
                    "url", targetUrl,
                    "status", conn.getResponseCode(),
                    "content", content.toString().substring(0, Math.min(5000, content.length()))
            ));
        } catch (Exception e) {
            return ResponseEntity.status(502).body(Map.of("error", e.getMessage()));
        }
    }

    // -----------------------------------------------------------------------
    // GET /api/files/download — VULNERABLE: CWE-22 (Path Traversal)
    // -----------------------------------------------------------------------
    @GetMapping("/files/download")
    public ResponseEntity<?> downloadFile(@RequestParam String filename) {
        try {
            // VULNERABLE: CWE-22 — No path validation; ../ sequences allowed
            Path filePath = Paths.get(UPLOADS_DIR, filename);
            if (!Files.exists(filePath)) {
                return ResponseEntity.notFound().build();
            }
            byte[] content = Files.readAllBytes(filePath);
            return ResponseEntity.ok()
                    .header("Content-Disposition", "attachment; filename=\"" + filename + "\"")
                    .body(new String(content));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    // -----------------------------------------------------------------------
    // POST /api/data/import — VULNERABLE: CWE-502 (Insecure Deserialization)
    // -----------------------------------------------------------------------
    @PostMapping("/data/import")
    public ResponseEntity<?> importData(@RequestBody byte[] data) {
        try {
            // VULNERABLE: CWE-502 — ObjectInputStream on untrusted data
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object obj = ois.readObject();
            ois.close();
            return ResponseEntity.ok(Map.of(
                    "imported", obj.toString(),
                    "type", obj.getClass().getName()
            ));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
