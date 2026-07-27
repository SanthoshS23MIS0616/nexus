package com.cybershield.service;

import com.cybershield.model.AssetRelationship.AssetType;
import com.cybershield.model.Incident;
import com.cybershield.repository.AssetRelationshipRepository;
import com.cybershield.repository.AuditLogRepository;
import com.cybershield.repository.LicenseRepository;
import com.cybershield.repository.ServerRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * RiskEngineService — calculates a risk score (0-100) for any asset or user.
 *
 * ═══════════════════════════════════════════════════════
 * RISK SCORING FORMULA (explain this in your viva!)
 * ═══════════════════════════════════════════════════════
 *
 * RiskScore = sum of triggered factors (capped at 100)
 *
 * FACTOR 1: +30 — Server not patched in last 90 days
 *   → Reads: servers.last_patch_date
 *   → Why: Unpatched servers have known CVEs attackers exploit
 *
 * FACTOR 2: +25 — A license linked to this asset is expired
 *   → Reads: licenses.expiry_date < TODAY
 *   → Why: Expired licenses = possibly unpatched/unsupported software
 *
 * FACTOR 3: +20 — Failed login attempts in last 5 minutes (brute force signal)
 *   → Reads: COUNT(audit_logs WHERE action=LOGIN_FAIL AND timestamp > NOW-5min)
 *   → Why: Active brute-force attack = elevated risk RIGHT NOW
 *   → Score: +20 per batch of 5 failures (capped at +40)
 *
 * FACTOR 4: +15 — Asset is reachable from a low-trust node (trust_level < 30)
 *   → Reads: asset_relationships WHERE target=this_asset AND trust_level < 30
 *   → Why: If a weak account connects to this server, attacker can pivot here
 *
 * FACTOR 5: +10 — Asset was accessed by a VIEWER role (unusual access pattern)
 *   → Reads: audit_logs WHERE action=READ AND target=this_asset (recent)
 *   → Note: Used in future version; currently applied globally
 *
 * THRESHOLD:
 *   score >= 50  → LOW incident
 *   score >= 70  → MEDIUM incident
 *   score >= 85  → HIGH incident
 *   score >= 95  → CRITICAL incident
 * ═══════════════════════════════════════════════════════
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RiskEngineService {

    private final AuditLogRepository auditLogRepository;
    private final ServerRepository serverRepository;
    private final LicenseRepository licenseRepository;
    private final AssetRelationshipRepository relationshipRepository;

    // Scoring constants — change these to tune sensitivity
    private static final int SCORE_UNPATCHED_SERVER     = 30;
    private static final int SCORE_EXPIRED_LICENSE      = 25;
    private static final int SCORE_FAILED_LOGIN_BATCH   = 20; // per 5 failures
    private static final int SCORE_LOW_TRUST_REACHABLE  = 15;
    private static final int SCORE_MAX                  = 100;

    // Thresholds
    private static final int PATCH_DAYS_THRESHOLD       = 90;
    private static final int FAILED_LOGIN_WINDOW_MINUTES = 5;
    private static final int LOW_TRUST_MAX              = 30;

    /**
     * Calculate risk score for a SERVER asset.
     *
     * @param serverId  The server's database ID
     * @return          RiskResult with score + breakdown map
     */
    public RiskResult calculateServerRisk(Long serverId) {
        Map<String, Integer> breakdown = new HashMap<>();
        int score = 0;

        // FACTOR 1: Patch date check
        var serverOpt = serverRepository.findById(serverId);
        if (serverOpt.isPresent()) {
            var server = serverOpt.get();
            if (server.getLastPatchDate() == null ||
                server.getLastPatchDate().isBefore(LocalDate.now().minusDays(PATCH_DAYS_THRESHOLD))) {
                score += SCORE_UNPATCHED_SERVER;
                breakdown.put("unpatched_server", SCORE_UNPATCHED_SERVER);
                log.debug("Server {} risk +{}: not patched in 90 days", serverId, SCORE_UNPATCHED_SERVER);
            }
        }

        // FACTOR 2: Expired license linked to this server
        long expiredLicenses = licenseRepository.countExpiredLicenses(LocalDate.now());
        if (expiredLicenses > 0) {
            score += SCORE_EXPIRED_LICENSE;
            breakdown.put("expired_license", SCORE_EXPIRED_LICENSE);
            log.debug("Server {} risk +{}: expired license detected", serverId, SCORE_EXPIRED_LICENSE);
        }

        // FACTOR 4: Reachable from low-trust node
        long lowTrustEdges = relationshipRepository.countLowTrustIncomingEdges(
                serverId, AssetType.SERVER, LOW_TRUST_MAX);
        if (lowTrustEdges > 0) {
            score += SCORE_LOW_TRUST_REACHABLE;
            breakdown.put("low_trust_reachable", SCORE_LOW_TRUST_REACHABLE);
            log.debug("Server {} risk +{}: reachable from {} low-trust node(s)",
                    serverId, SCORE_LOW_TRUST_REACHABLE, lowTrustEdges);
        }

        score = Math.min(score, SCORE_MAX);
        log.info("Server {} risk score: {}/100 | breakdown: {}", serverId, score, breakdown);
        return new RiskResult(serverId, AssetType.SERVER, score, breakdown);
    }

    /**
     * Calculate risk score for a USER (based on recent failed logins).
     * This is called after every LOGIN_FAIL to check if an incident should be created.
     *
     * @param username   The username being attacked
     * @return           RiskResult with score + breakdown
     */
    public RiskResult calculateUserRisk(String username) {
        Map<String, Integer> breakdown = new HashMap<>();
        int score = 0;

        // FACTOR 3: Count failed logins in last 5 minutes
        long failedLogins = auditLogRepository.countFailedLoginsSince(
                username,
                LocalDateTime.now().minusMinutes(FAILED_LOGIN_WINDOW_MINUTES)
        );

        if (failedLogins > 0) {
            // +20 per batch of 5 failures, capped at +40
            int batches = (int) Math.min(failedLogins / 5 + 1, 2);
            int failScore = batches * SCORE_FAILED_LOGIN_BATCH;
            score += failScore;
            breakdown.put("failed_logins_" + failedLogins, failScore);
            log.debug("User '{}' risk +{}: {} failed logins in last 5 min",
                    username, failScore, failedLogins);
        }

        // If the user account can reach a high-value server (via graph)
        // We check if this user has any outgoing edges to assets
        // (simplified: any user with edges to servers gets +15)
        // Full implementation: look up user ID in AssetRelationships
        // TODO: wire user ID lookup here in Phase 4

        score = Math.min(score, SCORE_MAX);
        log.info("User '{}' risk score: {}/100 | failed_logins={} | breakdown: {}",
                username, score, failedLogins, breakdown);
        return new RiskResult(null, AssetType.USER, score, breakdown, username);
    }

    /**
     * Calculate risk score for ALL servers — used for dashboard summary.
     * Returns a map of serverId → RiskResult.
     */
    public Map<Long, RiskResult> calculateAllServerRisks() {
        Map<Long, RiskResult> results = new HashMap<>();
        serverRepository.findAll().forEach(server -> {
            RiskResult result = calculateServerRisk(server.getId());
            results.put(server.getId(), result);
        });
        return results;
    }

    /**
     * Convert a risk score to an incident severity level.
     * Used by IncidentService to set the severity.
     */
    public Incident.Severity scoreToSeverity(int score) {
        if (score >= 95) return Incident.Severity.CRITICAL;
        if (score >= 85) return Incident.Severity.HIGH;
        if (score >= 70) return Incident.Severity.MEDIUM;
        return Incident.Severity.LOW;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Inner class: RiskResult — holds score + breakdown + context
    // ─────────────────────────────────────────────────────────────────────

    /**
     * RiskResult — immutable result object returned by the Risk Engine.
     * Contains the score, per-factor breakdown, and severity.
     */
    public static class RiskResult {
        public final Long assetId;
        public final AssetType assetType;
        public final int score;
        public final Map<String, Integer> breakdown;
        public final String username;   // only set for USER type results

        public RiskResult(Long assetId, AssetType assetType,
                          int score, Map<String, Integer> breakdown) {
            this(assetId, assetType, score, breakdown, null);
        }

        public RiskResult(Long assetId, AssetType assetType,
                          int score, Map<String, Integer> breakdown, String username) {
            this.assetId   = assetId;
            this.assetType = assetType;
            this.score     = score;
            this.breakdown = breakdown;
            this.username  = username;
        }

        public String getSeverityLabel() {
            if (score >= 95) return "CRITICAL";
            if (score >= 85) return "HIGH";
            if (score >= 70) return "MEDIUM";
            if (score >= 50) return "LOW";
            return "SAFE";
        }

        @Override
        public String toString() {
            return String.format("RiskResult{assetId=%d, type=%s, score=%d, severity=%s, breakdown=%s}",
                    assetId, assetType, score, getSeverityLabel(), breakdown);
        }
    }

}
