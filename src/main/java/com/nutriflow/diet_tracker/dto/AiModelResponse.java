package com.nutriflow.diet_tracker.dto;


import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter @Setter
public class AiModelResponse {
    private String title;
    private String quantity;
    private int energy;
    private float protein;
    private float carbohydrates;
    private float fat;
    private float fiber;
}

