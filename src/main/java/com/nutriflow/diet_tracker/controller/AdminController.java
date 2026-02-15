package com.nutriflow.diet_tracker.controller;

import com.nutriflow.diet_tracker.dto.AdminStatsDto;
import com.nutriflow.diet_tracker.service.AdminService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "http://localhost:5173") // Change to your frontend URL
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AdminService adminService;

    public AdminController(AdminService adminService) {
        this.adminService = adminService;
    }

    @GetMapping("/stats")
    public AdminStatsDto getAdminStats(@AuthenticationPrincipal Jwt jwt) {
        return adminService.getStats(jwt);
    }
}