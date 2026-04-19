<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Data Whitelist
    |--------------------------------------------------------------------------
    |
    | List of query parameters allowed to be stored in the 'payload' column.
    | Everything else will be filtered out for privacy and security reasons.
    |
    */
    'whitelist' => [
        'utm_source',
        'utm_medium',
        'utm_campaign',
        'utm_term',
        'utm_content',
        'ref',
    ],

    /*
    |--------------------------------------------------------------------------
    | IP Anonymization
    |--------------------------------------------------------------------------
    |
    | Whether to anonymize the IP address before saving it to the database.
    | This is highly recommended for GDPR/DSGVO compliance.
    |
    */
    'anonymize_ip' => true,

    /*
    |--------------------------------------------------------------------------
    | Bot Tracking
    |--------------------------------------------------------------------------
    |
    | Whether to track bot and crawler visits. If set to false, visits from
    | search engines and automated scanners will be ignored.
    | Requires the 'jaybizzle/crawler-detect' package.
    |
    */
    'track_bots' => false,

    /*
    |--------------------------------------------------------------------------
    | Exclusion Rules
    |--------------------------------------------------------------------------
    |
    | Define rules to skip tracking for specific requests.
    |
    */
    'exclude' => [
        /*
         * Paths that should not be logged. Supports wildcards (e.g., 'admin*').
         */
        'paths' => [
            'adminpanel*', // Administrative dashboard
            'livewire*',   // Livewire technical updates
            'horizon*',    // Laravel Horizon
            'telescope*',  // Laravel Telescope
        ],

        /*
         * Specific IP addresses that should be ignored.
         */
        'ips' => [
            // '127.0.0.1',
        ],

        /*
         * If true, visits from authenticated users will not be recorded.
         * Useful for filtering out your own activity while logged in.
         */
        'ignore_authenticated' => true,
    ],
];