package com.nutriflow.diet_tracker.controller;

import com.nutriflow.diet_tracker.dto.UserTargetDto;
import com.nutriflow.diet_tracker.entity.UserTarget;
import com.nutriflow.diet_tracker.service.FrontendService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "http://localhost:5173")
@RestController
@RequestMapping("/api/user/targets")
public class TargetController {
    private final FrontendService frontendService;

    public TargetController(FrontendService frontendService) {
        this.frontendService = frontendService;
    }

    @GetMapping
    public UserTarget getDailyTargets(@AuthenticationPrincipal Jwt jwt) {
        return frontendService.getTarget(jwt);
    }

    @PostMapping
    public UserTarget updateDailyTargets(@RequestBody UserTargetDto dto, @AuthenticationPrincipal Jwt jwt) {
        return frontendService.updateTarget(dto, jwt);
    }
}















