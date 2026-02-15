package com.nutriflow.diet_tracker.repository;

import com.nutriflow.diet_tracker.entity.FoodLog;
import com.nutriflow.diet_tracker.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;


@Repository
public interface FoodLogRepository extends JpaRepository<FoodLog,Long> {
    // Inside FoodLogRepository interface
    long countByCreatedAtAfter(LocalDateTime date);
    List<FoodLog> findByCreatedAtBetweenAndUser(LocalDateTime createdAtAfter, LocalDateTime createdAtBefore, User user);
}
