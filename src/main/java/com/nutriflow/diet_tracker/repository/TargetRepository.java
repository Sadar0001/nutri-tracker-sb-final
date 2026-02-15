package com.nutriflow.diet_tracker.repository;

import com.nutriflow.diet_tracker.entity.User;
import com.nutriflow.diet_tracker.entity.UserTarget;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TargetRepository extends JpaRepository<UserTarget, Long> {
    Optional<UserTarget> findByUser(User user);
}