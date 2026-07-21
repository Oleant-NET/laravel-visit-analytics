<?php

return [
    /**
     * The "Golden Window" for session-like correlation (in seconds).
     * * Since IPs are anonymized and no session IDs are stored, we use this 
     * tight window to group related requests. 60s is optimal to catch 
     * aggressive crawlers while avoiding false positives from shared subnets.
     */
    'session_window' => 60,

    /**
     * Request density threshold.
     * * Maximum allowed requests from the same anonymized IP and User-Agent 
     * combination within the 'session_window'. Exceeding this marks the 
     * entire burst as bot traffic.
     */
    'burst_threshold' => 15,

    /**
     * Data lookback depth (in minutes).
     * * How far back the cron job should look for unprocessed or 
     * recently flagged logs to perform its cleanup and correlation.
     * Recommended: Slightly longer than your cron frequency.
     */
    'lookback_minutes' => 15,

    /**
     * Evidence Settings for Retroactive Actions.
     * * Defines the metadata stored when the retro service upgrades a log.
     */
    'evidence' => [
        'source' => 'retroactive_service',
        'mark_as_bot_score' => 100,
    ],
];