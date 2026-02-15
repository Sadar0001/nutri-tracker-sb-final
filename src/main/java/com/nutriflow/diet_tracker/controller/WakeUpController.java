package com.nutriflow.diet_tracker.controller;

import com.nutriflow.diet_tracker.service.FrontendService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/public") // Public endpoint, no auth required
public class WakeUpController {

    private final FrontendService frontendService;

    public WakeUpController(FrontendService frontendService) {
        this.frontendService = frontendService;
    }

    @GetMapping("/wake-up")
    public String wakeUpServices() {
        // 1. Spring Boot is awake if this line runs.
        // 2. Now wake up Python AI
        String pythonStatus = "Offline";
        try {
            // Reusing your existing checkEngine method which calls Python /health
            pythonStatus = frontendService.checkEngine();
        } catch (Exception e) {
            System.out.println("Python service is still waking up...");
        }

        return "Spring: Awake | Python: " + pythonStatus;
    }
}