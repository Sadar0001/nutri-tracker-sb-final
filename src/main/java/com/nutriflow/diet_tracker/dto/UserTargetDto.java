package com.nutriflow.diet_tracker.dto;

import lombok.Data;

@Data
public class UserTargetDto {
    private float energyTarget;
    private float proteinTarget;
    private float carbsTarget;
    private float fiberTarget;
    private float fatTarget;
}