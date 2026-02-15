package com.nutriflow.diet_tracker.dto;

import lombok.*;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter @Setter
public class AiModelListResponse {
    private List<AiModelResponse> items;
}