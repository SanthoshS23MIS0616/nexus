package com.cybershield.controller;

import com.cybershield.model.AssetRelationship.AssetType;
import com.cybershield.service.IncidentService;
import com.cybershield.service.RiskEngineService;
import com.cybershield.service.RiskEngineService.RiskResult;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * RiskController — exposes Risk Engine results via REST API.
 *
 * Endpoints:
 *   GET /api/risk/server/{id}     → risk score for one server
 *   GET /api/risk/servers         → risk scores for ALL servers (dashboard)
 *   GET /api/risk/user/{username} → risk score for a user
 *   POST /api/risk/evaluate/server/{id} → evaluate + auto-create incident
 */
@RestController
@RequestMapping("/api/risk")
@RequiredArgsConstructor
public class RiskController {

    private final RiskEngineService riskEngineService;
    private final IncidentService incidentService;

    // Get risk score for a specific server
    @GetMapping("/server/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<Map<String, Object>> getServerRisk(@PathVariable Long id) {
        RiskResult result = riskEngineService.calculateServerRisk(id);
        return ResponseEntity.ok(Map.of(
                "assetId",   result.assetId,
                "assetType", result.assetType,
                "score",     result.score,
                "severity",  result.getSeverityLabel(),
                "breakdown", result.breakdown
        ));
    }

    // Get risk scores for ALL servers — used by dashboard risk panel
    @GetMapping("/servers")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN')")
    public ResponseEntity<Map<Long, Map<String, Object>>> getAllServerRisks() {
        Map<Long, RiskResult> allRisks = riskEngineService.calculateAllServerRisks();
        Map<Long, Map<String, Object>> response = new java.util.HashMap<>();
        allRisks.forEach((id, result) ->
            response.put(id, Map.of(
                    "score",    result.score,
                    "severity", result.getSeverityLabel(),
                    "breakdown", result.breakdown
            ))
        );
        return ResponseEntity.ok(response);
    }

    // Get risk score for a user (e.g., after seeing failed logins)
    @GetMapping("/user/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getUserRisk(@PathVariable String username) {
        RiskResult result = riskEngineService.calculateUserRisk(username);
        return ResponseEntity.ok(Map.of(
                "username",  username,
                "assetType", result.assetType,
                "score",     result.score,
                "severity",  result.getSeverityLabel(),
                "breakdown", result.breakdown
        ));
    }

    // Evaluate server risk + auto-create incident if score >= 50
    @PostMapping("/evaluate/server/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> evaluateServer(@PathVariable Long id) {
        var incident = incidentService.evaluateAndCreateServerIncident(id);
        RiskResult result = riskEngineService.calculateServerRisk(id);

        return ResponseEntity.ok(Map.of(
                "assetId",         id,
                "score",           result.score,
                "severity",        result.getSeverityLabel(),
                "breakdown",       result.breakdown,
                "incidentCreated", incident != null,
                "incidentId",      incident != null ? incident.getId() : "none"
        ));
    }
}
