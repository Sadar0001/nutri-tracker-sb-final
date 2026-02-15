package com.nutriflow.diet_tracker.dto;

import lombok.Data;

@Data
public class AdminStatsDto {
    private long totalUsers;
    private long totalLogs;
    private long logsToday;
    private long logsThisMonth;
    private long logsThisYear;
}