package com.nutriflow.diet_tracker;

import com.nutriflow.diet_tracker.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;


@SpringBootApplication
public class DietTrackerApplication {

	public static void main(String[] args) {
		SpringApplication.run(DietTrackerApplication.class, args);
	}

    @Bean
    CommandLineRunner initAdmin(UserRepository userRepository) {
        return args -> {
            // Use your EXACT Clerk ID from the screenshot
            String myClerkId = "user_39WJni5JjU2ugV2czXcZPUFKQ7m";

            userRepository.findByClerkId(myClerkId).ifPresentOrElse(user -> {
                user.setRole("ROLE_ADMIN");
                userRepository.save(user);
                System.out.println("✅ SUCCESS: Role updated to ROLE_ADMIN for: " + user.getEmail());
            }, () -> {
                System.out.println("❌ ERROR: Clerk ID not found in database. Please log in to the website first.");
            });
        };
    }
}
