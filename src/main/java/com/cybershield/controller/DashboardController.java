package com.cybershield.controller;

import com.cybershield.model.AuditLog;
import com.cybershield.model.License;
import com.cybershield.service.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * DashboardController — single endpoint returning all dashboard data.
 *
 * GET /api/dashboard returns:
 *   - counts       : asset totals + open incidents
 *   - expiredLicenses
 *   - expiringSoonLicenses
 *   - unpatchedServers
 *   - highRiskServerCount (score >= 70)
 *   - openIncidents
 *   - recentAuditLogs
 *   - totalAlerts  : badge count for the UI
 */
@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
public class DashboardController {

    private final ServerService serverService;
    private final FirewallService firewallService;
    private final LicenseService licenseService;
    private final HardwareService hardwareService;
    private final AuditLogService auditLogService;
    private final IncidentService incidentService;
    private final RiskEngineService riskEngineService;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<Map<String, Object>> getDashboard() {

        Map<String, Object> dashboard = new HashMap<>();

        // ── Asset Counts ──────────────────────────────────────────
        Map<String, Object> counts = new HashMap<>();
        counts.put("totalServers",    serverService.countTotal());
        counts.put("runningServers",  serverService.countRunning());
        counts.put("totalFirewalls",  firewallService.countTotal());
        counts.put("activeFirewalls", firewallService.countActive());
        counts.put("totalLicenses",   licenseService.countTotal());
        counts.put("expiredLicenses", licenseService.countExpired());
        counts.put("totalHardware",   hardwareService.countTotal());
        counts.put("openIncidents",   incidentService.countOpenIncidents());
        dashboard.put("counts", counts);

        // ── License Alerts ────────────────────────────────────────
        List<License> expired      = licenseService.getExpiredLicenses();
        List<License> expiringSoon = licenseService.getExpiringSoon();
        dashboard.put("expiredLicenses",      expired);
        dashboard.put("expiringSoonLicenses", expiringSoon);

        // ── Unpatched Servers ─────────────────────────────────────
        var unpatchedServers = serverService.getUnpatchedServers();
        dashboard.put("unpatchedServers", unpatchedServers);

        // ── Risk Summary ──────────────────────────────────────────
        var allRisks = riskEngineService.calculateAllServerRisks();
        long highRiskCount = allRisks.values().stream()
                .filter(r -> r.score >= 70).count();
        dashboard.put("highRiskServerCount", highRiskCount);

        // ── Open Incidents ────────────────────────────────────────
        dashboard.put("openIncidents", incidentService.getOpenIncidents());

        // ── Recent Audit Log ──────────────────────────────────────
        List<AuditLog> recentLogs = auditLogService.getRecentLogs();
        dashboard.put("recentAuditLogs", recentLogs);

        // ── Total Alert Badge Count ───────────────────────────────
        int totalAlerts = expired.size()
                + expiringSoon.size()
                + unpatchedServers.size()
                + (int) incidentService.countOpenIncidents();
        dashboard.put("totalAlerts", totalAlerts);

        return ResponseEntity.ok(dashboard);
    }
}
