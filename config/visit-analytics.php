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
    | Bot Detection Settings
    |--------------------------------------------------------------------------
    |
    | 'track_bots' (legacy): Instant filtering via User-Agent detection.
    | 'behavioral_analysis': Post-processing scoring of visits via Cron.
    |
    */
    'track_bots' => false, // Simple UA-based instant filter

    'behavioral_analysis' => [
        'enabled' => true,
        'threshold' => 70,
        'time_window' => 5,

        // Analysis settings
        'rate_limit_per_minute' => 30,
        'max_unique_paths' => 10,
        
        // Minimum time between requests to consider it "human" (in seconds)
        'min_interval' => 2, 

        // NEW: Max hits from same IP per day before applying incremental penalty
        'daily_hits_threshold' => 20,

        // Suspicious User-Agent fragments (Simple string matches)
        'suspicious_ua' => [
            'bot',
            'Chrome/7', 
            'MIUI', 
            'Headless', 
            'python-requests',
            'Palo Alto Networks',
            'Cortex-Xpanse',
            'compatible; MSIE 9.0; Windows NT 6.1',
            'SM-C5000',
            // Search Services    
            'Google-InspectionTool', 
            'bingbot',
            'Googlebot',
        ],

        // Obsolete OS versions (Windows XP, 2000, etc.)
        'obsolete_os' => [
            'Windows NT 5.0', 'Windows NT 5.1', 'Windows NT 5.2', 'Windows NT 6.0'
        ],

        // Advanced UA detection via Regular Expressions
        // Pattern '/Chrome\/\d+\.0\.0\.0/': Catches bots using fake "zero-build" versions
        'ua_regex_patterns' => [
            '/Chrome\/\d+\.0\.0\.0/' => 20, 
        ],

        // Public technical pages often targeted by crawlers before main content
        'tech_paths' => [
            'robots.txt',
            'login',
            'register',
            'sitemap.xml',
            'terms-of-use',
            'cookie-details',
            'privacy-policy',
        ],

        // Keywords to identify datacenters via reverse DNS lookup
        'datacenter_check' => [
            'enabled' => true,
            'keywords' => [
                'aws', 'amazon', 'googlecloud', 'google-proxy', 'digitalocean', 
                'hetzner', 'ovh', 'choopa', 'linode', 'm247', 'leaseweb',
                'hosting',
                'bloom.host',
                'server',
                'vps',
                'quadranet',
                'colocation',
                'dedicated',
                'at-vienna',
            ],
        ],

        // HoneyPot Path (Instant 100 score / Instant Ban)
        'honeypot_paths' => [
            '/.env',
            '/wp-admin',
            '/.git',
            '/bitrix',
            '/config.php',
            '/composer.lock',
            '/phpinfo.php',
        ],

        /*
        |--------------------------------------------------------------------------
        | Scoring Weights
        |--------------------------------------------------------------------------
        |
        | Each behavioral or technical anomaly adds points to the 'bot_score'.
        | If the total score reaches the 'threshold', the visit is marked as a bot.
        |
        */
        'weights' => [
            // High frequency of requests within the 'time_window'
            'rate'          => 50, 
            
            // Too many unique pages visited in a short period (crawling behavior)
            'paths'         => 60, 
            
            // Standard suspicious string found in the User-Agent
            'ua'            => 50, 
            
            // Direct access to subpages without a Referer header
            'no_referer'    => 35, 
            
            // Absence of a PTR record (Reverse DNS) for the IP address
            'no_dns_record' => 50, 
            
            // Interaction speed faster than a human could physically click (< 2s)
            'speed_anomaly' => 50, 
            
            // IP belongs to a known cloud provider or datacenter (AWS, Hetzner, etc.)
            'datacenter'    => 100,
            
            // Instant detection for accessing trap URLs like /.env or /wp-admin
            'honeypot'      => 100,
            
            /*
            |--------------------------------------------------------------------------
            | Advanced Detection Weights
            |--------------------------------------------------------------------------
            */
            
            // Penalty for ancient OS versions (Windows XP/2000) common in bot farms
            'obsolete_os'         => 60, 
            
            // For fake "futuristic" Chrome versions detected via regex (e.g., Chrome/147.x)
            'future_chrome_bonus' => 40, 
            
            // Pattern of accessing multiple technical files (robots.txt, sitemap, etc.)
            'tech_path_penalty'   => 40, 
            
            // Incremental penalty for high volume of daily hits from the same IP
            'daily_hits_increment' => 10, 
        ],
    ],

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
         * IP addresses or subnets that should be ignored.
         * The check is performed using the CIDR notation.
         * * Quick cheat sheet for subnet masks:
         * IPv4:
         * - 192.168.1.* => '192.168.1.0/24'
         * - 192.168.* => '192.168.0.0/16'
         * - 192.* => '192.0.0.0/8'
         * * IPv6:
         * - 2001:db8:a:b:* => '2001:db8:a:b::/64'  (Standard interface prefix)
         * - 2001:db8:a:* => '2001:db8:a::/48'    (Typical site prefix)
         * - 2001:db8:* => '2001:db8::/32'      (ISP level prefix)
         */
        'ips' => [
            // '127.0.0.1',
            // '192.168.100.0/24',
            // '2001:db8::/32',
        ],
        
        /**
         * Specific emails that should be ignored.
         */
        'emails' => [
            // 'admin@example.com',
        ],

        /*
         * If true, visits from authenticated users will not be recorded.
         * Useful for filtering out your own activity while logged in.
         */
        'ignore_authenticated' => false,
    ],
];