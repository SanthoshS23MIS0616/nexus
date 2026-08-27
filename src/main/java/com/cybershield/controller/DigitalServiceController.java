package com.cybershield.controller;

import com.cybershield.model.DigitalService;
import com.cybershield.service.DigitalServiceService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * DigitalServiceController — REST API for NEDI digital service status.
 *
 * GET /api/services      → list all 8 NEDI services with health status
 */
@RestController
@RequestMapping("/api/services")
@RequiredArgsConstructor
public class DigitalServiceController {

    private final DigitalServiceService digitalServiceService;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<DigitalService>> getAllServices() {
        return ResponseEntity.ok(digitalServiceService.getAllServices());
    }
}
