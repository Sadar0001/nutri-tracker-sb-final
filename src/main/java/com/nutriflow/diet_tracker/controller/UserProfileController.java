package com.nutriflow.diet_tracker.controller;

import com.nutriflow.diet_tracker.entity.User;
import com.nutriflow.diet_tracker.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/users")
public class UserProfileController {

    @Autowired
    private UserRepository userRepository;

    // D://new eram project//diet-tracker//diet-tracker//src//main//java//com//nutriflow//diet_tracker//controller//UserProfileController.java

    @PostMapping("/sync")
    public User syncProfile(@AuthenticationPrincipal Jwt jwt, @RequestBody User profileData) {
        String clerkId = jwt.getSubject();
        String emailFromJwt = jwt.getClaimAsString("email");

        User user = userRepository.findByClerkId(clerkId).orElseGet(() -> {
            User newUser = new User();
            newUser.setRole("ROLE_USER");
            return newUser;
        });

        user.setClerkId(clerkId);
        user.setEmail(emailFromJwt); // This saves your real email
        user.setAge(profileData.getAge());
        user.setGender(profileData.getGender());
        user.setWeight(profileData.getWeight());
        user.setHeight(profileData.getHeight());
        user.setBmi(profileData.getBmi());

        return userRepository.save(user);
    }
}