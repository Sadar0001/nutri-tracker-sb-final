package com.nutriflow.diet_tracker.service;

import com.nutriflow.diet_tracker.dto.AdminStatsDto;
import com.nutriflow.diet_tracker.entity.User;
import com.nutriflow.diet_tracker.repository.FoodLogRepository;
import com.nutriflow.diet_tracker.repository.UserRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Service
public class AdminService {

    private final UserRepository userRepository;
    private final FoodLogRepository foodLogRepository;

    public AdminService(UserRepository userRepository, FoodLogRepository foodLogRepository) {
        this.userRepository = userRepository;
        this.foodLogRepository = foodLogRepository;
    }

    public AdminStatsDto getStats(Jwt jwt) {
        String clerkId = jwt.getSubject();

        User user = userRepository.findByClerkId(clerkId)
                .orElseThrow(() -> new RuntimeException("User not found!"));

        // Double check just to be safe
        if (!"ROLE_ADMIN".equals(user.getRole())) {
            throw new RuntimeException("Unauthorized Access");
        }

        AdminStatsDto stats = new AdminStatsDto();
        stats.setTotalUsers(userRepository.count());
        stats.setTotalLogs(foodLogRepository.count());

        LocalDateTime startOfDay = LocalDate.now().atStartOfDay();
        LocalDateTime startOfMonth = LocalDate.now().withDayOfMonth(1).atStartOfDay();
        LocalDateTime startOfYear = LocalDate.now().withDayOfYear(1).atStartOfDay();

        stats.setLogsToday(foodLogRepository.countByCreatedAtAfter(startOfDay));
        stats.setLogsThisMonth(foodLogRepository.countByCreatedAtAfter(startOfMonth));
        stats.setLogsThisYear(foodLogRepository.countByCreatedAtAfter(startOfYear));

        return stats;
    }
}