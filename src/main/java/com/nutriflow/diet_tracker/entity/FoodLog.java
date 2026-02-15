package com.nutriflow.diet_tracker.entity;


import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name="food_logs")
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class FoodLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name="food_name",nullable = false)
    private String foodName;
    private String quantity;
    private float protein;
    private float energy;
    private float carbohydrates;
    private float fiber;
    private float fat;

    @Column(nullable = false,updatable = false)
    private LocalDateTime createdAt;

    @ManyToOne
    @JoinColumn(name="user_id")
    @JsonIgnore
    private User user;
}
