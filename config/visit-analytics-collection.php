<?php

return [
    /**
     * Anonymization settings for GDPR/DSGVO compliance.
     * * These settings control how and when visitor IP addresses are masked
     * to protect user privacy after the analysis process is complete.
     */
    'anonymization' => [
        /**
         * IP Anonymization
         * 
         * If enabled, the last octet of IPv4 (or the last 80 bits of IPv6) 
         * will be masked before saving to the database. 
         * Highly recommended for GDPR/DSGVO compliance.
         */
        'anonymize_ip' => env('VISIT_ANALYTICS_ANONYMIZE_IP', true),

        /**
         * User Agent Anonymization
         * * If enabled, the 'user_agent' field will be cleared or truncated
         * after the retention period, removing browser-specific fingerprints.
         */
        'anonymize_ua' => env('VISIT_ANALYTICS_ANONYMIZE_UA', true),

        /**
         * Request Headers Anonymization
         * * If enabled, request headers stored in the logs will be cleared
         * after the retention period to prevent tracking via unique header combinations.
         */
        'anonymize_headers' => env('VISIT_ANALYTICS_ANONYMIZE_HEADERS', true),

        /**
         * Fingerprint Hash Anonymization
         * * If enabled, the 'fingerprint_hash' field will be replaced with the 
         * defined placeholder after the retention period, ensuring that 
         * individual user sessions cannot be tracked over long periods.
         */
        'anonymize_fingerprint_hash' => env('VISIT_ANALYTICS_ANONYMIZE_FINGERPRINT_HASH', true),

        /**
         * Placeholder for anonymized fingerprint hashes.
         */
        'fingerprint_placeholder' => 'anonym-sha256-ready',
        
        /**
         * IP Anonymization Mode
         *
         * 'sync'  - Anonymize IP immediately in Middleware. High privacy, less data for analysis.
         * 'async' - Anonymize IP later via Cron after bot analysis. High precision, temporary PII storage.
         *
         * Default: 'sync'
         */
        'anonymize_mode' => env('VISIT_ANALYTICS_ANONYMIZE_MODE', 'sync'),

        /**
         * Anonymize Detected Bots
         *
         * If true, even logs identified as bots will be anonymized after analysis.
         * If false, full IP addresses of bots will be preserved for security 
         * purposes (e.g., for manual blacklisting or Fail2Ban integration).
         *
         * Note: Setting this to 'false' may require a mention in your Privacy Policy.
         * Default: true
         */
        'anonymize_bots' => env('VISIT_ANALYTICS_ANONYMIZE_BOTS', true),

        /**
         * The retention period in minutes for keeping raw IP addresses.
         * * Raw IP addresses are stored for this duration to allow retroactive 
         * analysis, botnet cluster detection, and behavioral pattern recognition. 
         * Once this period expires, IPs will be irreversibly masked.
         * * Default: 30 minutes.
         */
        'anonymize_retention_minutes' => env('VISIT_ANALYTICS_ANONYMIZE_RETENTION_MINUTES', 30),
    ],
    
    /**
     * Query Parameter Whitelist
     * 
     * Only these parameters from the request URL will be stored in 
     * the 'payload' column. All other parameters will be stripped 
     * to ensure privacy and database cleanliness.
     */
    'whitelist_params' => [
        'utm_source',
        'utm_medium',
        'utm_campaign',
        'utm_term',
        'utm_content',
        'ref',
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

    /*
    |--------------------------------------------------------------------------
    | Fingerprinting Headers
    |--------------------------------------------------------------------------
    |
    | This list defines the specific HTTP headers used to identify and 
    | analyze incoming traffic. These headers are essential for 
    | distinguishing legitimate browsers from automated bots.
    |
    */

    /**
     * Cookie logging strategy.
     * 'full' - store the entire cookie header (caution: session hijacking risk).
     * 'exists' - store only a boolean indicating if cookies were present.
     * 'none' - completely ignore cookies even if present in target_headers.
     */
    'cookie_mode' => 'exists',

    'target_headers' => [
        /**
         * State persistence check.
         * Used to verify if the client supports and returns cookies 
         * on subsequent requests within the same session.
         */
        'cookie',

        /**
         * Client Hints: Provides the brand and major version of the browser.
         * Modern Chromium-based browsers (Chrome 110+) use this instead of 
         * full versions in the User-Agent string.
         */
        'sec-ch-ua',

        /**
         * Client Hints: Identifies the user's operating system.
         * Used to cross-verify against the OS reported in the User-Agent.
         */
        'sec-ch-ua-platform',

        /**
         * Client Hints: Indicates if the user is on a mobile device.
         * Essential for differentiating mobile traffic from desktop-emulated bots.
         */
        'sec-ch-ua-mobile',

        /**
         * Fetch Metadata: Describes the relationship between the request 
         * initiator's origin and the target resource's origin.
         */
        'sec-fetch-site',

        /**
         * Fetch Metadata: Indicates the request's destination (e.g., 'document', 'empty').
         * Critical for detecting headless browsers making atypical requests.
         */
        'sec-fetch-dest',

        /**
         * Fetch Metadata: Specifies the request mode (e.g., 'cors', 'navigate').
         * Helps distinguish between top-level navigation and background API/resource fetching.
         */
        'sec-fetch-mode',


        /**
         * Preferred languages of the user. 
         * Most legitimate users have localized settings, while many basic 
         * bots omit this header entirely.
         */
        'accept-language',

        /**
         * Supported compression methods (e.g., gzip, br).
         * Browsers always support compression; lack of this header is 
         * a strong indicator of a primitive script.
         */
        'accept-encoding',
        
        /**
         * Used to identify Ajax requests (XMLHttpRequest).
         * Commonly sent by JavaScript frameworks (like Axios or jQuery).
         * Legitimate direct navigations omit this, but generic headless 
         * bots or API scrapers sometimes fake or misconfigure it.
         */
        'x-requested-with',

        /**
         * Client Hints (High-Entropy): The exact version of the operating system.
         * Legitimate browsers only send this after an 'Accept-CH' challenge. 
         * If present on the very first "cold" request, it strongly indicates 
         * an over-engineered bot spoofing its fingerprint.
         */
        'sec-ch-ua-platform-version',

        /**
         * Client Hints (High-Entropy): The device model (e.g., 'Pixel 6' or '').
         * For desktop browsers, it is usually empty. If a desktop User-Agent 
         * comes with a populated mobile model name (or vice versa), it is a 
         * dead giveaway of an inconsistent bot fingerprint.
         */
        'sec-ch-ua-model',

        /**
         * Client Hints (High-Entropy): The underlying device architecture (e.g., 'x86' or 'arm').
         * Extremely useful for cross-verifying against the CPU info found in 
         * the User-Agent string to detect poorly randomized fake headers.
         */
        'sec-ch-ua-arch',

        /**
         * Client Hints (High-Entropy): The complete list of brands and full versions.
         * While 'sec-ch-ua' only gives the major version (e.g., '143'), this header 
         * contains the full build version. Essential for future advanced telemetry.
         */
        'sec-ch-ua-full-version-list',
    ],

    /**
     * Desktop/Mobile-Platform, Popular Browsers in User-Agent-String
     */
    'user_agent_parsing' => [
        'desktop-platforms' => ['Windows', 'Macintosh', 'Linux'],
        'mobile_platforms' => ['Android', 'iPhone', 'iPad', 'Windows Phone', 'BlackBerry'],
        'browsers' => ['Firefox', 'Chrome', 'Safari', 'Edge', 'Opera', 'MSIE', 'Trident'],
    ],
];