package com.cybershield.repository;

import com.cybershield.model.License;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;

@Repository
public interface LicenseRepository extends JpaRepository<License, Long> {

    // Dashboard: licenses expired
    @Query("SELECT l FROM License l WHERE l.expiryDate < :today")
    List<License> findExpiredLicenses(@Param("today") LocalDate today);

    // Dashboard: expiring within 30 days
    @Query("SELECT l FROM License l WHERE l.expiryDate >= :today AND l.expiryDate <= :in30days")
    List<License> findExpiringSoon(@Param("today") LocalDate today,
                                   @Param("in30days") LocalDate in30days);

    // Risk Engine: count expired licenses (used in overall risk score)
    @Query("SELECT COUNT(l) FROM License l WHERE l.expiryDate < :today")
    long countExpiredLicenses(@Param("today") LocalDate today);
}
