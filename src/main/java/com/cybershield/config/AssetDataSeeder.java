package com.cybershield.config;

import com.cybershield.model.*;
import com.cybershield.model.AssetRelationship.AssetType;
import com.cybershield.model.AssetRelationship.RelationshipType;
import com.cybershield.model.Server.ServerStatus;
import com.cybershield.model.Firewall.FirewallStatus;
import com.cybershield.model.License.LicenseStatus;
import com.cybershield.model.License.LicenseType;
import com.cybershield.model.Hardware.HardwareStatus;
import com.cybershield.model.Hardware.HardwareType;
import com.cybershield.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.time.LocalDate;

/**
 * AssetDataSeeder — seeds servers, firewalls, licenses, and hardware
 * with realistic data designed to tell the demo story.
 *
 * Story: The 'viewer' account connects through Firewall-Edge →
 *        Server-App → Server-DB — this path is what BFS will find.
 *
 * Some assets are intentionally "bad" (unpatched / expired license)
 * so the Risk Engine has data to score.
 *
 * Runs AFTER DataInitializer (Order 2).
 */
@Component
@Order(2)
@RequiredArgsConstructor
@Slf4j
public class AssetDataSeeder implements CommandLineRunner {

    private final ServerRepository serverRepository;
    private final FirewallRepository firewallRepository;
    private final LicenseRepository licenseRepository;
    private final HardwareRepository hardwareRepository;
    private final AssetRelationshipRepository relationshipRepository;

    @Override
    public void run(String... args) {
        if (serverRepository.count() == 0) {
            seedServers();
            seedFirewalls();
            seedLicenses();
            seedHardware();
            log.info("Asset seed data loaded successfully");
        } else {
            log.debug("Assets already seeded — skipping asset seed");
        }

        // Graph seeding is always checked independently
        seedGraph();
    }

    private void seedServers() {
        // PATCHED server — recent patch date (low risk)
        serverRepository.save(Server.builder()
                .name("Server-Web-01").ipAddress("10.0.1.10")
                .operatingSystem("Ubuntu").osVersion("22.04 LTS")
                .status(ServerStatus.RUNNING).location("Rack A1")
                .owner("viewer")                       // owned by viewer account → IDOR demo target
                .cpuCores(8).ramGb(32).storageGb(500)
                .lastPatchDate(LocalDate.now().minusDays(10))  // recently patched
                .warrantyExpiry(LocalDate.now().plusYears(2))
                .notes("Frontend web server").build());

        // UNPATCHED server — 120 days old patch (HIGH risk +30)
        serverRepository.save(Server.builder()
                .name("Server-App-02").ipAddress("10.0.1.11")
                .operatingSystem("CentOS").osVersion("7.9")
                .status(ServerStatus.RUNNING).location("Rack A2")
                .owner("serveradmin")
                .cpuCores(16).ramGb(64).storageGb(1000)
                .lastPatchDate(LocalDate.now().minusDays(120))  // UNPATCHED → risk +30
                .warrantyExpiry(LocalDate.now().plusYears(1))
                .notes("Application server — UNPATCHED").build());

        // CRITICAL DATABASE SERVER — unpatched + connected to expired license (highest risk)
        serverRepository.save(Server.builder()
                .name("Server-DB-03").ipAddress("10.0.1.12")
                .operatingSystem("Windows Server").osVersion("2019")
                .status(ServerStatus.RUNNING).location("Rack A3")
                .owner("admin")
                .cpuCores(32).ramGb(128).storageGb(5000)
                .lastPatchDate(LocalDate.now().minusDays(95))   // UNPATCHED → risk +30
                .warrantyExpiry(LocalDate.now().plusMonths(3))
                .notes("Primary database server — HIGH VALUE TARGET").build());

        // Stopped server
        serverRepository.save(Server.builder()
                .name("Server-Backup-04").ipAddress("10.0.1.13")
                .operatingSystem("Ubuntu").osVersion("20.04 LTS")
                .status(ServerStatus.STOPPED).location("Rack B1")
                .owner("serveradmin")
                .cpuCores(4).ramGb(16).storageGb(2000)
                .lastPatchDate(LocalDate.now().minusDays(30))
                .notes("Backup server — currently offline").build());

        // Maintenance server
        serverRepository.save(Server.builder()
                .name("Server-Dev-05").ipAddress("10.0.1.14")
                .operatingSystem("Ubuntu").osVersion("22.04 LTS")
                .status(ServerStatus.MAINTENANCE).location("Rack B2")
                .owner("serveradmin")
                .cpuCores(8).ramGb(32).storageGb(500)
                .lastPatchDate(LocalDate.now().minusDays(5))
                .notes("Dev/test server — in maintenance").build());

        log.info("Seeded 5 servers");
    }

    private void seedFirewalls() {
        // Edge firewall — gateway to internal network (attack entry point)
        firewallRepository.save(Firewall.builder()
                .name("Firewall-Edge-01").vendor("Cisco").model("ASA 5505")
                .ipAddress("10.0.0.1").firmwareVersion("9.8.4")
                .status(FirewallStatus.ACTIVE).location("DMZ Rack")
                .activeRulesCount(142)
                .lastRuleReviewDate(LocalDate.now().minusDays(45))
                .lastFirmwareUpdate(LocalDate.now().minusDays(200))  // outdated firmware
                .warrantyExpiry(LocalDate.now().plusYears(1))
                .notes("Primary edge firewall — OUTDATED FIRMWARE").build());

        // Internal firewall — patched
        firewallRepository.save(Firewall.builder()
                .name("Firewall-Internal-02").vendor("Palo Alto").model("PA-220")
                .ipAddress("10.0.1.1").firmwareVersion("10.2.3")
                .status(FirewallStatus.ACTIVE).location("Core Rack")
                .activeRulesCount(89)
                .lastRuleReviewDate(LocalDate.now().minusDays(15))
                .lastFirmwareUpdate(LocalDate.now().minusDays(20))
                .warrantyExpiry(LocalDate.now().plusYears(2))
                .notes("Internal segment firewall — up to date").build());

        // DB firewall — protects database servers
        firewallRepository.save(Firewall.builder()
                .name("Firewall-DB-03").vendor("Fortinet").model("FortiGate 60F")
                .ipAddress("10.0.1.50").firmwareVersion("7.2.1")
                .status(FirewallStatus.ACTIVE).location("DB Rack")
                .activeRulesCount(55)
                .lastRuleReviewDate(LocalDate.now().minusDays(7))
                .lastFirmwareUpdate(LocalDate.now().minusDays(30))
                .warrantyExpiry(LocalDate.now().plusYears(3))
                .notes("Database zone firewall").build());

        log.info("Seeded 3 firewalls");
    }

    private void seedLicenses() {
        // EXPIRED license — used by Server-DB-03 (triggers risk +25)
        licenseRepository.save(License.builder()
                .softwareName("Oracle Database 19c").vendor("Oracle")
                .licenseType(LicenseType.PER_SEAT).totalSeats(5).usedSeats(5)
                .expiryDate(LocalDate.now().minusDays(30))  // EXPIRED
                .purchaseDate(LocalDate.now().minusYears(3))
                .renewalCost(45000.00).assignedTo("Server-DB-03")
                .status(LicenseStatus.EXPIRED)
                .notes("CRITICAL: Expired Oracle license — non-compliant").build());

        // Expiring soon — warning alert
        licenseRepository.save(License.builder()
                .softwareName("Windows Server 2022").vendor("Microsoft")
                .licenseType(LicenseType.PER_SEAT).totalSeats(10).usedSeats(7)
                .expiryDate(LocalDate.now().plusDays(15))  // EXPIRING SOON
                .purchaseDate(LocalDate.now().minusYears(1))
                .renewalCost(12000.00).assignedTo("Server-Web-01")
                .status(LicenseStatus.PENDING_RENEWAL)
                .notes("Renewal needed within 15 days").build());

        // Healthy active license
        licenseRepository.save(License.builder()
                .softwareName("CrowdStrike Falcon").vendor("CrowdStrike")
                .licenseType(LicenseType.SUBSCRIPTION).totalSeats(50).usedSeats(23)
                .expiryDate(LocalDate.now().plusYears(1))
                .purchaseDate(LocalDate.now().minusMonths(3))
                .renewalCost(8500.00).assignedTo("All Servers")
                .status(LicenseStatus.ACTIVE)
                .notes("Endpoint security — active and healthy").build());

        // Another active license
        licenseRepository.save(License.builder()
                .softwareName("Red Hat Enterprise Linux").vendor("Red Hat")
                .licenseType(LicenseType.SUBSCRIPTION).totalSeats(5).usedSeats(3)
                .expiryDate(LocalDate.now().plusMonths(8))
                .purchaseDate(LocalDate.now().minusMonths(4))
                .renewalCost(6000.00).assignedTo("Server-App-02")
                .status(LicenseStatus.ACTIVE)
                .notes("RHEL subscription for app servers").build());

        log.info("Seeded 4 licenses (1 expired, 1 expiring soon, 2 active)");
    }

    private void seedHardware() {
        hardwareRepository.save(Hardware.builder()
                .assetTag("AICTE-SW-001").name("Core Switch Layer-3")
                .hardwareType(HardwareType.SWITCH).manufacturer("Cisco")
                .model("Catalyst 3750").serialNumber("CAT3750-001")
                .location("Core Rack, Slot 1").status(HardwareStatus.IN_USE)
                .purchaseDate(LocalDate.now().minusYears(3))
                .warrantyExpiry(LocalDate.now().plusMonths(6))
                .lastMaintenanceDate(LocalDate.now().minusDays(60))
                .nextMaintenanceDate(LocalDate.now().plusDays(30))
                .notes("Primary layer-3 switch — connects all VLANs").build());

        hardwareRepository.save(Hardware.builder()
                .assetTag("AICTE-LB-001").name("Load Balancer Primary")
                .hardwareType(HardwareType.LOAD_BALANCER).manufacturer("F5")
                .model("BIG-IP 2000s").serialNumber("F5-LB-001")
                .location("DMZ Rack, Slot 3").status(HardwareStatus.IN_USE)
                .purchaseDate(LocalDate.now().minusYears(2))
                .warrantyExpiry(LocalDate.now().plusYears(1))
                .lastMaintenanceDate(LocalDate.now().minusDays(30))
                .nextMaintenanceDate(LocalDate.now().plusDays(60))
                .notes("Distributes traffic to web servers").build());

        hardwareRepository.save(Hardware.builder()
                .assetTag("AICTE-UPS-001").name("UPS Unit A")
                .hardwareType(HardwareType.UPS).manufacturer("APC")
                .model("Smart-UPS 3000").serialNumber("APC-UPS-001")
                .location("Rack A, Power Unit").status(HardwareStatus.IN_USE)
                .purchaseDate(LocalDate.now().minusYears(4))
                .warrantyExpiry(LocalDate.now().minusDays(10)) // WARRANTY EXPIRED
                .lastMaintenanceDate(LocalDate.now().minusDays(90))
                .nextMaintenanceDate(LocalDate.now().plusDays(0)) // DUE NOW
                .notes("UPS for Rack A — WARRANTY EXPIRED, maintenance overdue").build());

        log.info("Seeded 3 hardware assets");
    }

    /**
     * seedGraph() — creates 15 directed edges forming the attack path.
     *
     * THE DEMO STORY:
     *   viewer(USER:3) is compromised → attacker pivots through:
     *   Firewall-Edge-01 → Server-Web-01 → Server-App-02 → Server-DB-03
     *
     * Edge IDs (after seeding):
     *   Users:     admin=1, serveradmin=2, viewer=3
     *   Servers:   Web-01=1, App-02=2, DB-03=3, Backup-04=4, Dev-05=5
     *   Firewalls: Edge-01=1, Internal-02=2, DB-03=3
     *   Licenses:  Oracle=1, Windows=2, CrowdStrike=3, RHEL=4
     *   Hardware:  Switch=1, LB=2, UPS=3
     *
     * ATTACK PATH (BFS will find this):
     *   USER:3 → FIREWALL:1 → SERVER:1 → SERVER:2 → SERVER:3
     */
    private void seedGraph() {
        if (relationshipRepository.count() > 0) {
            log.debug("Graph edges already seeded — skipping");
            return;
        }

        // Helper lambda to build and save one edge
        java.util.function.Consumer<AssetRelationship> save = relationshipRepository::save;

        // ── USER → FIREWALL edges (entry points) ─────────────────────────
        // viewer user connects to Edge firewall (LOW trust = easy to compromise)
        save.accept(AssetRelationship.builder()
                .sourceAssetId(3L).sourceType(AssetType.USER)         // viewer
                .targetAssetId(1L).targetType(AssetType.FIREWALL)     // Firewall-Edge-01
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(20)   // LOW trust — attacker entry point
                .build());

        // serveradmin connects to Internal firewall
        save.accept(AssetRelationship.builder()
                .sourceAssetId(2L).sourceType(AssetType.USER)         // serveradmin
                .targetAssetId(2L).targetType(AssetType.FIREWALL)     // Firewall-Internal-02
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(70)
                .build());

        // admin connects to all firewalls (full access)
        save.accept(AssetRelationship.builder()
                .sourceAssetId(1L).sourceType(AssetType.USER)         // admin
                .targetAssetId(1L).targetType(AssetType.FIREWALL)     // Firewall-Edge-01
                .relationshipType(RelationshipType.MANAGES)
                .trustLevel(90)
                .build());

        // ── FIREWALL → SERVER edges (pivot points) ───────────────────────
        // Edge firewall connects to Web server (LOW trust — exposed DMZ)
        save.accept(AssetRelationship.builder()
                .sourceAssetId(1L).sourceType(AssetType.FIREWALL)     // Firewall-Edge-01
                .targetAssetId(1L).targetType(AssetType.SERVER)       // Server-Web-01
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(25)   // LOW — DMZ server, internet-facing
                .build());

        // Edge firewall also sees Dev server
        save.accept(AssetRelationship.builder()
                .sourceAssetId(1L).sourceType(AssetType.FIREWALL)     // Firewall-Edge-01
                .targetAssetId(5L).targetType(AssetType.SERVER)       // Server-Dev-05
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(30)
                .build());

        // Internal firewall connects to App server
        save.accept(AssetRelationship.builder()
                .sourceAssetId(2L).sourceType(AssetType.FIREWALL)     // Firewall-Internal-02
                .targetAssetId(2L).targetType(AssetType.SERVER)       // Server-App-02
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(50)
                .build());

        // DB firewall connects to DB server
        save.accept(AssetRelationship.builder()
                .sourceAssetId(3L).sourceType(AssetType.FIREWALL)     // Firewall-DB-03
                .targetAssetId(3L).targetType(AssetType.SERVER)       // Server-DB-03
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(60)
                .build());

        // ── SERVER → SERVER edges (lateral movement) ─────────────────────
        // Web server can reach App server (lateral pivot — CRITICAL path)
        save.accept(AssetRelationship.builder()
                .sourceAssetId(1L).sourceType(AssetType.SERVER)       // Server-Web-01
                .targetAssetId(2L).targetType(AssetType.SERVER)       // Server-App-02
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(40)   // Medium-low — attacker can pivot here
                .build());

        // App server can reach DB server (CRITICAL lateral move)
        save.accept(AssetRelationship.builder()
                .sourceAssetId(2L).sourceType(AssetType.SERVER)       // Server-App-02
                .targetAssetId(3L).targetType(AssetType.SERVER)       // Server-DB-03
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(55)   // App → DB is common but risky
                .build());

        // Backup server connects to DB (backup job)
        save.accept(AssetRelationship.builder()
                .sourceAssetId(4L).sourceType(AssetType.SERVER)       // Server-Backup-04
                .targetAssetId(3L).targetType(AssetType.SERVER)       // Server-DB-03
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(45)
                .build());

        // ── SERVER → LICENSE edges (asset dependency) ────────────────────
        // DB server hosts the Oracle license (expired — risk +25)
        save.accept(AssetRelationship.builder()
                .sourceAssetId(3L).sourceType(AssetType.SERVER)       // Server-DB-03
                .targetAssetId(1L).targetType(AssetType.LICENSE)      // Oracle DB (EXPIRED)
                .relationshipType(RelationshipType.HOSTS)
                .trustLevel(80)
                .build());

        // Web server hosts Windows Server license
        save.accept(AssetRelationship.builder()
                .sourceAssetId(1L).sourceType(AssetType.SERVER)       // Server-Web-01
                .targetAssetId(2L).targetType(AssetType.LICENSE)      // Windows Server
                .relationshipType(RelationshipType.HOSTS)
                .trustLevel(80)
                .build());

        // ── HARDWARE → SERVER edges (infrastructure) ─────────────────────
        // Core switch connects to all servers (infrastructure layer)
        save.accept(AssetRelationship.builder()
                .sourceAssetId(1L).sourceType(AssetType.HARDWARE)     // Core Switch
                .targetAssetId(1L).targetType(AssetType.SERVER)       // Server-Web-01
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(85)
                .build());

        // Load balancer connects to Web server
        save.accept(AssetRelationship.builder()
                .sourceAssetId(2L).sourceType(AssetType.HARDWARE)     // Load Balancer
                .targetAssetId(1L).targetType(AssetType.SERVER)       // Server-Web-01
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(75)
                .build());

        // Load balancer connects to App server
        save.accept(AssetRelationship.builder()
                .sourceAssetId(2L).sourceType(AssetType.HARDWARE)     // Load Balancer
                .targetAssetId(2L).targetType(AssetType.SERVER)       // Server-App-02
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(75)
                .build());

        log.info("Seeded 15 graph edges — attack path: USER:3 → FW:1 → SRV:1 → SRV:2 → SRV:3");
    }
}
