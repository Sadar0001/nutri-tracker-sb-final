package com.nutriflow.diet_tracker.service;

import com.nutriflow.diet_tracker.dto.AiModelListResponse;
import com.nutriflow.diet_tracker.dto.AiModelResponse;
import com.nutriflow.diet_tracker.dto.FoodLogDto;
import com.nutriflow.diet_tracker.dto.UserTargetDto;
import com.nutriflow.diet_tracker.entity.FoodLog;
import com.nutriflow.diet_tracker.entity.User;
import com.nutriflow.diet_tracker.entity.UserTarget;
import com.nutriflow.diet_tracker.repository.FoodLogRepository;
import com.nutriflow.diet_tracker.repository.TargetRepository;
import com.nutriflow.diet_tracker.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class FrontendService {
    private final RestClient restClient;
    private final UserRepository userRepository;
    private final FoodLogRepository foodLogRepository;
    private final TargetRepository targetRepository;

    // Hardcoded Admin ID - The Master Key
    private static final String ADMIN_CLERK_ID = "user_39WJni5JjU2ugV2czXcZPUFKQ7m";

    // UPDATED CONSTRUCTOR
    public FrontendService(RestClient.Builder builder,
                           UserRepository userRepository,
                           FoodLogRepository foodLogRepository,
                           TargetRepository targetRepository,
                           @Value("${ai.service.url}") String aiServiceUrl) { // INJECTED HERE

        this.foodLogRepository = foodLogRepository;
        this.userRepository = userRepository;
        this.targetRepository = targetRepository;

        this.restClient = builder
                .requestFactory(new SimpleClientHttpRequestFactory())
                .baseUrl(aiServiceUrl) // USED HERE
                .build();
    }

    public String checkEngine(){
        return restClient.get()
                .uri("/health")
                .retrieve()
                .body(String.class);
    }

    // --- CORE USER LOGIC WITH SILENT ADMIN UPGRADE ---
    public User getUser(Jwt jwt) {
        String clerkId = jwt.getSubject();

        return userRepository.findByClerkId(clerkId)
                .map(user -> {
                    if (ADMIN_CLERK_ID.equals(clerkId) && !"ROLE_ADMIN".equals(user.getRole())) {
                        System.out.println("⚠️ Elevating user " + user.getEmail() + " to ADMIN.");
                        user.setRole("ROLE_ADMIN");
                        return userRepository.save(user);
                    }
                    return user;
                })
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setClerkId(clerkId);
                    String email = jwt.getClaimAsString("email");
                    newUser.setEmail(email != null ? email : "user_" + clerkId.substring(0,5) + "@nutriflow.com");

                    if (ADMIN_CLERK_ID.equals(clerkId)) {
                        newUser.setRole("ROLE_ADMIN");
                    } else {
                        newUser.setRole("ROLE_USER");
                    }
                    return userRepository.save(newUser);
                });
    }

    // ... (Rest of your methods remain exactly the same) ...

    // --- LOGGING LOGIC ---
    public FoodLog addLog(FoodLogDto log, Jwt jwt) {
        User user = getUser(jwt);
        FoodLog foodLog = new FoodLog();
        foodLog.setFoodName(log.getFoodName());
        foodLog.setQuantity(log.getQuantity());
        foodLog.setCarbohydrates(log.getCarbohydrates());
        foodLog.setFiber(log.getFiber());
        foodLog.setProtein(log.getProtein());
        foodLog.setEnergy(log.getEnergy());
        foodLog.setFat(log.getFat());
        foodLog.setUser(user);
        foodLog.setCreatedAt(LocalDateTime.now());
        return foodLogRepository.save(foodLog);
    }

    public List<FoodLog> getLogs(LocalDateTime from, LocalDateTime to, Jwt jwt) {
        User user = getUser(jwt);
        return foodLogRepository.findByCreatedAtBetweenAndUser(from, to, user);
    }

    public boolean deleteLog(Long id, Jwt jwt) {
        User user = getUser(jwt);
        FoodLog log = foodLogRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Log not found"));

        if (!log.getUser().getId().equals(user.getId())) {
            throw new RuntimeException("Unauthorized: You cannot delete someone else's log");
        }
        foodLogRepository.delete(log);
        return true;
    }

    // --- AI INTEGRATION ---
    public List<FoodLog> addByItem(String item, String quantity, Jwt jwt) {
        String prompt = "I have " + item + " " + quantity;
        return getQuery(prompt, jwt);
    }

    public List<FoodLog> getQuery(String prompt, Jwt jwt) {
        Map<String, String> map = Map.of("query", prompt);
        try {
            AiModelListResponse listResponse = restClient.post()
                    .uri("/query")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(map)
                    .retrieve()
                    .body(AiModelListResponse.class);

            List<FoodLog> savedLogs = new ArrayList<>();
            if (listResponse != null && listResponse.getItems() != null) {
                for (AiModelResponse item : listResponse.getItems()) {
                    savedLogs.add(saveAiResponse(item, jwt));
                }
            }
            return savedLogs;
        } catch (HttpClientErrorException.BadRequest e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "AI could not process query.");
        }
    }

    public FoodLog addByImage(String base64Img, Jwt jwt) {
        Map<String, String> map = new HashMap<>();
        map.put("image_base64", base64Img);
        try {
            AiModelResponse aiModelResponse = restClient.post()
                    .uri("/image")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(map)
                    .retrieve()
                    .body(AiModelResponse.class);
            return saveAiResponse(aiModelResponse, jwt);
        } catch (HttpClientErrorException.BadRequest e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid image.");
        }
    }

    private FoodLog saveAiResponse(AiModelResponse res, Jwt jwt) {
        User user = getUser(jwt);
        FoodLog log = new FoodLog();
        log.setFoodName(res.getTitle());
        log.setQuantity(res.getQuantity());
        log.setEnergy(res.getEnergy());
        log.setProtein(res.getProtein());
        log.setCarbohydrates(res.getCarbohydrates());
        log.setFat(res.getFat());
        log.setFiber(res.getFiber());
        log.setCreatedAt(LocalDateTime.now());
        log.setUser(user);
        return foodLogRepository.save(log);
    }

    // --- TARGET LOGIC ---
    public UserTarget getTarget(Jwt jwt) {
        User user = getUser(jwt);
        return targetRepository.findByUser(user).orElseGet(() -> {
            UserTarget defaultTarget = new UserTarget();
            defaultTarget.setEnergyTarget(2000f);
            defaultTarget.setProteinTarget(150f);
            defaultTarget.setCarbsTarget(250f);
            defaultTarget.setFiberTarget(30f);
            defaultTarget.setFatTarget(70f);
            defaultTarget.setUser(user);
            return targetRepository.save(defaultTarget);
        });
    }

    public UserTarget updateTarget(UserTargetDto dto, Jwt jwt) {
        User user = getUser(jwt);
        UserTarget target = targetRepository.findByUser(user).orElse(new UserTarget());
        target.setEnergyTarget(dto.getEnergyTarget());
        target.setProteinTarget(dto.getProteinTarget());
        target.setCarbsTarget(dto.getCarbsTarget());
        target.setFiberTarget(dto.getFiberTarget());
        target.setFatTarget(dto.getFatTarget());
        target.setUser(user);
        return targetRepository.save(target);
    }
}