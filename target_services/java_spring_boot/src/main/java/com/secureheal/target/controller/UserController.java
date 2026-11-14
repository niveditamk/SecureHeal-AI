// =============================================================================
// WARNING: THIS FILE CONTAINS INTENTIONAL VULNERABILITIES FOR SECURITY RESEARCH.
// DO NOT DEPLOY IN PRODUCTION. Every vulnerability is marked: VULNERABLE: CWE-XXX
// =============================================================================
package com.secureheal.target.controller;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @PersistenceContext
    private EntityManager entityManager;

    // -----------------------------------------------------------------------
    // POST /api/users/search — VULNERABLE: CWE-89 (SQL Injection)
    // -----------------------------------------------------------------------
    @PostMapping("/search")
    public ResponseEntity<?> searchUsers(@RequestBody Map<String, String> body) {
        String searchQuery = body.getOrDefault("query", "");
        // VULNERABLE: CWE-89 — User input concatenated into SQL string
        String sql = "SELECT u FROM User u WHERE u.username LIKE '%" + searchQuery + "%'";
        Query query = entityManager.createQuery(sql);
        List<?> results = query.getResultList();
        return ResponseEntity.ok(Map.of("results", results, "query", sql));
    }

    // -----------------------------------------------------------------------
    // GET /api/users/{id}/profile — VULNERABLE: CWE-79 (XSS)
    // -----------------------------------------------------------------------
    @GetMapping(value = "/{id}/profile", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> getUserProfile(@PathVariable Long id) {
        com.secureheal.target.model.User user = entityManager.find(
                com.secureheal.target.model.User.class, id);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        // VULNERABLE: CWE-79 — User data rendered as raw HTML without escaping
        String html = "<html><body>" +
                "<h1>Profile: " + user.getUsername() + "</h1>" +
                "<p>Email: " + user.getEmail() + "</p>" +
                "<p>Role: " + user.getRole() + "</p>" +
                "<p>Bio: " + user.getBio() + "</p>" +
                "</body></html>";
        return ResponseEntity.ok(html);
    }

    // -----------------------------------------------------------------------
    // GET /api/admin/reports — VULNERABLE: CWE-862 (Missing Authorization)
    // -----------------------------------------------------------------------
    @GetMapping("/admin/reports")
    public ResponseEntity<?> getAdminReports() {
        // VULNERABLE: CWE-862 — No authentication or authorization check
        List<?> users = entityManager.createQuery("SELECT u FROM User u").getResultList();
        return ResponseEntity.ok(Map.of(
                "report", "Confidential Admin Report",
                "total_users", users.size(),
                "users", users,
                "db_password", com.secureheal.target.config.AppConfig.DB_PASSWORD
        ));
    }
}
