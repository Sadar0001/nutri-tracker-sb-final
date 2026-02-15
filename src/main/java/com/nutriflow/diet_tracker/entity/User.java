package com.nutriflow.diet_tracker.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "users")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // THE BRIDGE: Store Clerk's unique User ID (e.g., user_2l...)
    @Column(nullable = false, unique = true)
    private String clerkId;

    @Column(unique = true)
    private String email;

    private String firstName;
    private String lastName;

    // Extra Fields
    private int age;
    private String gender;
    private float weight;
    private float height;
    private float bmi;

    // Simple Role handling (Stored as a String in DB for simplicity)
    private String role = "ROLE_USER";

    @OneToMany(mappedBy="user", cascade=CascadeType.ALL)
    private List<FoodLog> foodLogList = new ArrayList<>();

    // Add this inside com.nutriflow.diet_tracker.entity.User
    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL)
    private UserTarget userTarget;
}