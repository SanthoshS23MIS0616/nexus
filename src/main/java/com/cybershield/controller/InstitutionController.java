package com.cybershield.controller;

import com.cybershield.model.Institution;
import com.cybershield.service.InstitutionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * InstitutionController exposes the representative NEDI institutions used by
 * the cybersecurity command-center scenario.
 */
@RestController
@RequestMapping("/api/institutions")
@RequiredArgsConstructor
public class InstitutionController {

    private final InstitutionService institutionService;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<Institution>> getAll() {
        return ResponseEntity.ok(institutionService.getAll());
    }
}
