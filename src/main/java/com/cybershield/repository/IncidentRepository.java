package com.cybershield.repository;

import com.cybershield.model.Incident;
import com.cybershield.model.Incident.IncidentStatus;
import com.cybershield.model.Incident.Severity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * IncidentRepository — queries for incident management and dashboard display.
 */
@Repository
public interface IncidentRepository extends JpaRepository<Incident, Long> {

    // Dashboard: get all open incidents ordered by newest first
    List<Incident> findByStatusOrderByCreatedAtDesc(IncidentStatus status);

    // Dashboard: get recent incidents regardless of status
    List<Incident> findTop20ByOrderByCreatedAtDesc();

    // Filter by severity
    List<Incident> findBySeverityOrderByCreatedAtDesc(Severity severity);

    // Count open incidents (for dashboard alert badge)
    long countByStatus(IncidentStatus status);

    // Prevent duplicate incident creation for same asset in short time
    boolean existsByRelatedAssetIdAndStatusIn(Long assetId, List<IncidentStatus> statuses);
}
