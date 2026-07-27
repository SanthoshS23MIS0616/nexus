package com.cybershield.controller;

import com.cybershield.model.Incident;
import com.cybershield.service.IncidentService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * IncidentController — REST API for viewing and managing security incidents.
 *
 * Endpoints:
 *   GET  /api/incidents            → all recent incidents (ADMIN, SERVER_ADMIN)
 *   GET  /api/incidents/open       → open incidents only
 *   GET  /api/incidents/count      → count of open incidents (dashboard badge)
 *   PUT  /api/incidents/{id}/resolve      → mark as RESOLVED (ADMIN only)
 *   PUT  /api/incidents/{id}/investigate  → mark as INVESTIGATING
 */
@RestController
@RequestMapping("/api/incidents")
@RequiredArgsConstructor
public class IncidentController {

    private final IncidentService incidentService;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<List<Incident>> getAllIncidents() {
        return ResponseEntity.ok(incidentService.getAllIncidents());
    }

    @GetMapping("/open")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<List<Incident>> getOpenIncidents() {
        return ResponseEntity.ok(incidentService.getOpenIncidents());
    }

    @GetMapping("/count")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<Map<String, Long>> getOpenCount() {
        return ResponseEntity.ok(Map.of("openIncidents", incidentService.countOpenIncidents()));
    }

    @PutMapping("/{id}/resolve")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> resolve(@PathVariable Long id,
                                     @AuthenticationPrincipal UserDetails userDetails) {
        try {
            Incident resolved = incidentService.resolveIncident(id, userDetails.getUsername());
            return ResponseEntity.ok(resolved);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PutMapping("/{id}/investigate")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<?> investigate(@PathVariable Long id) {
        try {
            return ResponseEntity.ok(incidentService.markInvestigating(id));
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
