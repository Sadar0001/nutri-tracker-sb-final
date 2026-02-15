package com.nutriflow.diet_tracker.controller;

import com.nutriflow.diet_tracker.dto.FoodLogDto;
import com.nutriflow.diet_tracker.entity.FoodLog;
import com.nutriflow.diet_tracker.service.FrontendService;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@CrossOrigin(origins = "http://localhost:5173")
@RestController
@RequestMapping("/api/user")
public class FrontendController {
    private final FrontendService frontendService;

    public FrontendController(FrontendService frontendService) {
        this.frontendService = frontendService;
    }

    // FIXED: Now returns List<FoodLog>
    @PostMapping("/search")
    public List<FoodLog> searchItem(@RequestBody Map<String, String> payload,@RequestParam String quantity,@AuthenticationPrincipal Jwt jwt) {
        String item = payload.get("item");
        return frontendService.addByItem(item,quantity,jwt);
    }

    // FIXED: Now returns List<FoodLog>
    @PostMapping("/query")
    public List<FoodLog> searchQuery(@RequestBody Map<String, String> payload, @AuthenticationPrincipal Jwt jwt) {
        String query = payload.get("query");
        return frontendService.getQuery(query,jwt);
    }

    @PostMapping("/image")
    public FoodLog imageItem(@RequestBody Map<String, String>payload,@AuthenticationPrincipal Jwt jwt) {
        String base64Img = payload.get("image_base64");
        return frontendService.addByImage(base64Img,jwt);
    }

    @GetMapping("/logs")
    public List<FoodLog> getLogs(
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @AuthenticationPrincipal Jwt jwt
    ) {
        return frontendService.getLogs(from,to,jwt);
    }

    @PostMapping("/logs")
    public FoodLog createLog(@RequestBody FoodLogDto log, @AuthenticationPrincipal Jwt jwt) {
        return frontendService.addLog(log,jwt);
    }

    @GetMapping("/check-engine")
    public String checkEngine() {
        return frontendService.checkEngine();
    }

    @DeleteMapping("/delete")
    public void deleteItem(@RequestParam Long id, @AuthenticationPrincipal Jwt jwt) {
        frontendService.deleteLog(id, jwt);
    }
}