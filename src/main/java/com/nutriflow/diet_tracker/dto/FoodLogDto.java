package com.nutriflow.diet_tracker.dto;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter @Setter
public class FoodLogDto {

    private String foodName;
    private String quantity;
    private float protein;
    private float energy;
    private float carbohydrates;
    private float fiber;
    private float fat;

}


