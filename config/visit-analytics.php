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

        /**
         * Analysis settings
         */ 
        'rate_limit_per_minute' => 30,
        'max_unique_paths' => 10,

        /**
         * The time window (in minutes) to check for session depth.
         * 
         * This is used to detect slow crawlers or automated scanners that 
         * access a single URL without a referer and then disappear.
         * If no other activity from the same IP is found within this 
         * window (before or after), the visit is considered suspicious.
         */
        'depth_check_window' => 60,
        
        /**
         * Minimum time between requests to consider it "human" (in seconds)
         */
        'min_interval' => 2, 

        /**
         * Max hits from same IP per day before applying incremental penalty 
         */
        'daily_hits_threshold' => 20,

        /**
         * 1. EXPLICIT BOTS (Official Search Engines)
         * These are identified as bots but are generally allowed for SEO.
         * They will be marked as 'is_official_bot' in the database.
         */
        'explicit_bots' => [
            'bot',
            '+http',
            'googlebot',
            'bingbot',
            'yandexbot',
            'duckduckbot',
            'baiduspider',
            'facebot',
            'ia_archiver',
            'applebot',
        ],

        /**
         * 2. SUSPICIOUS USER-AGENTS (Common fragments)
         * Common library or tool strings used by scrapers and automated tools.
         */
        'suspicious_ua' => [
            'MIUI', 
            'Headless', 
            'python-requests',
            'Palo Alto Networks',
            'CFNetwork',
            'Cortex-Xpanse',
            'compatible',
            'guzzlehttp',
            'go-http-client',
            'curl',
            'php-requests',
            'java',
            'wget',
            'bun',
            'ruby',
        ],

        /**
         * 3. CUMULATIVE PENALTY (The Snowball Effect)
         * Progressive scoring for repeated violations from the same IP address.
         * Helps catch stealthy bots that behave well initially.
         */
        'cumulative' => [
            'enabled' => true,
            'history_window_hours' => 24, // How far back to check for previous violations
            'no_referer_window_minutes' => 10, // Time window (in minutes) to look back for previous direct hits (minutes)
            'no_referer_increment' => 20, // Extra points added for repeated direct access
        ],

        /**
         * Obsolete OS versions (Windows XP, 2000, etc.) 
         */
        'obsolete_os' => [
            'Windows NT 5',
            'Windows NT 6',
            'Mac OS X 10',
        ],

        /**
         * Advanced UA detection via Regular Expressions
         * Pattern '/\d+\.0\.0\.0/': Catches bots using fake "zero-build" versions 
         */
        'ua_regex_patterns' => [
            '/\d+\.0\.0\.0/' => 35, 
        ],

        /**
         * Public technical pages often targeted by crawlers before main content 
         */
        'tech_paths' => [
            'robots.txt',
            'login',
            'register',
            'sitemap.xml',
            'terms-of-use',
            'cookie-details',
            'privacy-policy',
        ],

        /**
         * 4. SUSPICIOUS REFERER PORTS
         * Technical ports in the Referer header (cPanel, Plesk, etc.) 
         * Real users almost never arrive from these ports.
         */
        'port_leak' => [
            2082, 2083, // cPanel
            2086, 2087, // WHM
            8443, 8880, // Plesk
            2222,       // DirectAdmin
            10000,      // Webmin
        ],

        /**
         * Keywords to identify datacenters via reverse DNS lookup 
         */
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
                'dataline',
            ],
        ],

        /**
         * HoneyPot Path (Instant 100 score / Instant Ban) 
         */
        'honeypot_paths' => [
            '/.env',
            '/wp-admin',
            '/.git',
            '/bitrix',
            '/config.php',
            '/composer.lock',
            '/phpinfo.php',
            '/.aws/credentials',
            '/.vscode/sftp.json',
            '/actuator/health',
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
            'rate'           => 50, 
            
            // Too many unique pages visited in a short period (crawling behavior)
            'paths'          => 60, 
            
            // Standard suspicious string found in the User-Agent
            'ua_suspicious'  => 50, 

            // Matches found in the 'explicit_bots' list
            'ua_explicit'    => 100, 
            
            // Direct access to subpages without a Referer header
            'no_referer'     => 35, 

            /**
             * Referer Loop Detection
             * Added to catch bots that set Referer equal to the current URL 
             * across multiple page requests.
             */
            'referer_loop' => 50,
            
            // Absence of a PTR record (Reverse DNS) for the IP address
            'no_dns_record' => 50, 
            
            // Interaction speed faster than a human could physically click (< 2s)
            'speed_anomaly' => 50, 
            
            // IP belongs to a known cloud provider or datacenter (AWS, Hetzner, etc.)
            'datacenter'    => 100,
            
            // Instant detection for accessing trap URLs like /.env or /wp-admin
            'honeypot'      => 100,

            /**
             * Score points added for single-page visits with no referer.
             * Recommended value: 20-30 (to be used as a contributing factor).
             */
            'single_visit' => 25,
            
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

            // Traffic arriving from technical panel ports (:2082, etc.)
            'port_leak' => 100,
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