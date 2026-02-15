package com.nutriflow.diet_tracker.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "user_targets")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class UserTarget {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private float energyTarget; // kcal
    private float proteinTarget; // g
    private float carbsTarget; // g
    private float fiberTarget; // g
    private float fatTarget; // g

    @OneToOne
    @JoinColumn(name = "user_id", unique = true)
    @JsonIgnore
    private User user;
}