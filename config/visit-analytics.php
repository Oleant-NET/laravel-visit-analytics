<?php

return [
    /**
     * Data Collection & Middleware Filtering
     * 
     * Configures how the 'TrackVisits' middleware captures request data.
     * Use this section to define data privacy rules and early-exit filters.
     */
    'collection' => [

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

    ],

    /**
     * Detection Engine Configuration
     * 
     * This is the core of the visit analysis system. It defines the total 
     * bot threshold and manages the registry of independent analyzers.
     */
    'detection_engine' => [
        'enabled'   => true,
        
        'threshold' => 70, // Total score to flag a visit as a bot

        /**
         * Registry of Bot Analyzers
         * 
         * Each analyzer must implement the BotAnalyzerInterface.
         * The engine iterates through enabled analyzers and aggregates their scores.
         */
        'analyzers' => [

            /**
             * Explicit Bot Identification
             * 
             * Performs a fast signature check for bots that openly identify 
             * themselves in the User-Agent header. This marks the visit 
             * as an 'official_bot' in the state.
             */
            'explicit_bots' => [
                'enabled' => true,
                'class'   => \Oleant\VisitAnalytics\Analyzers\ExplicitBotsAnalyzer::class,
                'params'  => [
                    
                    /**
                     * List of substrings to identify known/official bots.
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
                        'telegrambot',
                        'twitterbot',
                        'slackbot',
                    ],

                    'weights' => [
                        /**
                         * Penalty for explicit bots.
                         * Usually 100, meaning an immediate match with the threshold.
                         */
                        'ua_explicit' => 100,
                    ],
                ],
            ],

            /*
            |--------------------------------------------------------------------------
            | Header Integrity Analyzer Settings
            |--------------------------------------------------------------------------
            |
            | This analyzer verifies the presence and consistency of HTTP headers.
            | Legitimate browsers send a predictable set of headers, while basic 
            | scripts and bots often omit them to save bandwidth or due to poor 
            | emulation.
            |
            */
            'header_integrity' => [
                'enabled' => true,
                'class'   => \Oleant\VisitAnalytics\Analyzers\HeaderIntegrityAnalyzer::class,
                'params'  => [
                    /**
                     * Minimum Header Count Check
                     * 
                     * Total number of target headers that must be present in the request.
                     * Real browsers typically send 5-10 headers for a standard GET request.
                     */
                    'min_total_headers' => [
                        'count' => 5,
                        'score' => 30,
                    ],

                    /**
                     * Weighted Mandatory Headers
                     * * Specific headers and their respective threat scores if missing.
                     * 'sec-ch-' headers are automatically skipped for non-Chromium browsers
                     * to avoid false positives.
                     */
                    'weights' => [
                        'accept-language'      => 15, // Legitimate users almost always have a locale
                        'accept-encoding'      => 10, // Standard browsers always support compression
                        'sec-fetch-dest'       => 5, // Modern Fetch Metadata (Chrome 80+, Firefox 90+)
                        'sec-fetch-site'       => 5, // Helps identify request origin relationship
                        'sec-fetch-mode'       => 5, // Verifies the request mode
                        'sec-ch-ua'            => 15, // Essential for modern Chromium identification
                        'sec-ch-ua-platform'   => 5, // Essential for cross-verifying OS
                        'sec-ch-ua-mobile'     => 5, // Essential for cross-verifying device type
                    ],

                    /**
                     * Consistency & Cross-Verification Checks
                     * * Logic to detect bot spoofing by identifying logical conflicts 
                     * between the User-Agent string and the provided Client Hints.
                     */
                    'consistency_checks' => [
                        
                        /**
                         * High-Entropy Header Detection
                         * Detects bots that over-engineer their fingerprint by sending 
                         * high-entropy hints on the very first (cold) request.
                         */
                        'high_entropy' => [
                            'enabled' => true,
                            'score'   => 20,
                            'headers' => [
                                'sec-ch-ua-platform-version',
                                'sec-ch-ua-full-version-list',
                                'sec-ch-ua-model',
                            ],
                        ],

                        /**
                         * Platform Consistency
                         * Cross-verifies OS signals between User-Agent and sec-ch-ua-platform.
                         */
                        'os_platform_mismatch' => [
                            'enabled' => true,
                            'score'   => 50,
                        ],

                        /**
                         * Architecture Consistency
                         * Validates CPU architecture consistency (e.g., x86 vs arm).
                         */
                        'arch_architecture_mismatch' => [
                            'enabled' => true,
                            'score'   => 25,
                        ],
                    ],
                ],
            ],

            /**
             * User-Agent Integrity & Client Hints Verification
             * 
             * Analyzes the User-Agent string for suspicious patterns and 
             * cross-verifies it with modern Sec-CH-UA headers to detect 
             * sophisticated spoofing attempts.
             */
            'user_agent' => [
                'enabled' => true,
                'class'   => \Oleant\VisitAnalytics\Analyzers\UserAgentAnalyzer::class,
                'params'  => [
                    
                    /*
                    * List of legitimate browser rendering engine identifiers.
                    * Modern browsers consistently include one of these in their User-Agent strings
                    * to ensure compatibility and feature detection.
                    */
                    'browser_engines' => [
                        'AppleWebKit', // Chrome, Safari, Edge, Opera, Brave, Vivaldi
                        'Gecko',       // Firefox, Thunderbird, SeaMonkey
                        'Trident',     // IE 11 and older (legacy support)
                        'Blink',       // Modern Chrome/Edge engine
                        'KHTML',       // Historical engine (WebKit ancestor)
                        'Presto',      // Legacy Opera
                        'Goanna',      // Pale Moon browser engine
                        'Servo',       // Experimental/modern engine (e.g., Firefox components)
                    ],

                    /**
                     * Regex Patterns for Advanced Detection
                     * 'requires_verification' triggers cross-check with Client Hints.
                     */
                    'ua_regex_patterns' => [
                        'reduced_ua' => [
                            'pattern' => '/\d+\.0\.0\.0/', 
                            'weight'  => 20,
                            'requires_verification' => true,
                        ],
                        'headless_chrome' => [
                            'pattern' => '/HeadlessChrome/i',
                            'weight'  => 100,
                            'requires_verification' => false,
                        ],
                    ],

                    /**
                     * OS Mapping for Cross-Verification
                     * Maps UA tokens to expected 'sec-ch-ua-platform' values.
                     */
                    'os_mapping' => [
                        'Windows'   => 'Windows',
                        'Android'   => 'Android',
                        'Macintosh' => 'macOS',
                        'iPhone'    => 'iOS',
                        'iPad'      => 'iOS',
                        'Linux'     => 'Linux',
                        'CrOS'      => 'Chrome OS',
                    ],

                    /**
                     * Scoring Weights for UA Anomalies
                     */
                    'weights' => [
                        'missing_ua'         => 100, // No UA provided
                        'ua_suspicious'      => 50,  // Keyword match
                        'verification_failed' => 80,  // Client Hints mismatch (Spoofing)
                    ],
                ],
            ],

            /**
             * Obsolete Operating System Detection
             * 
             * Flags visitors reporting OS versions that are functionally dead for 
             * mainstream human traffic in 2026. Useful for catching legacy 
             * scraping scripts and old botnet drones.
             */
            'obsolete_os' => [
                'enabled' => true,
                'class'   => \Oleant\VisitAnalytics\Analyzers\ObsoleteOSAnalyzer::class,
                'params'  => [
                    
                    /**
                     * List of substrings to identify outdated operating systems.
                     * 
                     * Windows NT 5.x: Windows XP / 2000 / Server 2003
                     * Windows NT 6.0-6.3: Vista / 7 / 8 / 8.1
                     * Mac OS X 10.x: Versions prior to Big Sur (11.0)
                     */
                    'target_os' => [
                        'Windows 95',
                        'Win95',
                        'Windows 98',
                        'Win98',
                        'Windows ME',
                        'Windows NT 5.', 
                        'Windows NT 6.0', 
                        'Windows NT 6.1', 
                        'Windows NT 6.2', 
                        'Windows NT 6.3', 
                        'Mac OS X 10', // Older macOS versions
                        'Android 4.',
                        'Android 5.',
                        'Android 6.',
                    ],
                    /**
                     * Explicitly blacklisted browser signatures.
                     * 
                     * Contains fragments of User-Agent strings for browsers that are 
                     * considered functionally extinct for human traffic in 2026.
                     * 
                     * - MSIE / Trident: Internet Explorer (all versions), officially retired.
                     * - Opera/8, Opera/9: Legacy Presto-based versions, often used by 
                     *   low-quality scraping scripts.
                     * 
                     * Presence of these strings typically indicates automated tools, 
                     * legacy botnets, or abandoned crawlers.
                     */
                    'target_browsers' => [
                        'MSIE',      // Internet Explorer 10 and below
                        'Trident/',  // Internet Explorer 11
                        'Opera/8',   // Ancient Opera versions
                        'Opera/9',
                    ],

                    'weights' => [
                        /**
                         * Penalty score for using an obsolete OS.
                         * Default is 35+35, which is close to the typical bot threshold.
                         */
                        'obsolete_os'       => 35,
                        'obsolete_browsers' => 35,
                    ],
                ],
            ],

            /*
            |--------------------------------------------------------------------------
            | Outdated Browser Detection Settings
            |--------------------------------------------------------------------------
            |
            | Here you can configure the scoring system for users with old browsers.
            | Modern browsers (Chrome, Firefox, etc.) update automatically every 4 weeks.
            | A significant lag in version numbers often indicates automation tools,
            | headless browsers, or abandoned scraping scripts.
            |
            */
            'outdated_browser' => [
                /** @var bool Enable or disable the \Oleant\VisitAnalytics\Analyzers\OutdatedBrowserAnalyzer */
                'enabled' => true,
                'class'   => \Oleant\VisitAnalytics\Analyzers\OutdatedBrowserAnalyzer::class,
                'params'  => [
                    /** 
                     * Reference versions for May 2026.
                     * It is recommended to keep these values close to current stable releases.
                     */
                    'current_versions' => [
                        'chrome'  => 147,
                        'firefox' => 150,
                        'safari'  => 19,
                        'edge'    => 147,
                        'opera'   => 131,
                        'ie'      => 11,
                    ],


                    /**
                     * Scoring thresholds based on the version difference (delta).
                     * 
                     * diff:  The difference between current_version and user_version.
                     * score: The amount of bot_score points to add.
                     */
                    'scoring' => [
                        'minor_lag' => [
                            'description' => 'User is slightly behind, likely a normal delay.',
                            'diff'        => 5,
                            'score'       => 10,
                        ],
                        'moderate_lag' => [
                            'description' => 'Suspicious lag, typical for older automation environments.',
                            'diff'        => 10,
                            'score'       => 25,
                        ],
                        'ancient_lag' => [
                            'description' => 'Extremely outdated. High probability of a legacy bot.',
                            'diff'        => 20,
                            'score'       => 50,
                        ],
                    ],
                ],
            ],

            /**
             * Honeypot Trap Analyzer
             * * Detects scanners and malicious bots attempting to access sensitive 
             * or hidden paths. Hits on these paths are considered critical 
             * and usually result in an immediate bot classification.
             */
            'honeypots' => [
                'enabled' => true,
                'class'   => \Oleant\VisitAnalytics\Analyzers\HoneypotAnalyzer::class,
                'params'  => [

                    /**
                     * List of URL fragments used as traps.
                     * If the current URL contains any of these strings, the trap is sprung.
                     */
                    'honeypot_paths' => [
                        '/.env',
                        '/.git',
                        '/wp-admin',
                        '/wp-login',
                        '/bitrix',
                        '/config.php',
                        '/composer.lock',
                        '/phpinfo.php',
                        '/.aws/credentials',
                        '/.vscode/sftp.json',
                        '/actuator/health',
                    ],

                    'weights' => [
                        /**
                         * Penalty for hitting a honeypot.
                         * Default is 100, which triggers an immediate 'is_bot' status.
                         */
                        'honeypot' => 100,
                    ],
                ],
            ],

            /**
             * Referer Integrity & Navigation Analysis
             * * Analyzes how the visitor arrived at the site. Detects suspicious 
             * port leaks, impossible self-referrals, and cumulative penalties 
             * for repeated direct hits (no referer).
             */
            'referer' => [
                'enabled' => true,
                'class'   => \Oleant\VisitAnalytics\Analyzers\RefererAnalyzer::class,
                'params'  => [

                    /**
                     * Port Leak Detection
                     * Technical ports in the Referer header often indicate traffic 
                     * coming from hosting panels, proxy managers, or automated tools.
                     */
                    'port_leak' => [
                        2082, 2083, // cPanel
                        2086, 2087, // WHM
                        8443, 8880, // Plesk
                        2222,       // DirectAdmin
                        10000,      // Webmin
                        8888,       // Common proxy/dev port
                    ],

                    /**
                     * Cumulative "Snowball" Penalty
                     * Increases the score if the same IP makes multiple direct hits 
                     * (no referer) within a short time window.
                     */
                    'cumulative' => [
                        'enabled' => true,
                        'no_referer_window_minutes' => 10,
                        'no_referer_increment'      => 20, // Extra points per repeated hit
                        'session_window' => fn() => config('visit-analytics.retro_analysis.session_window', 60),
                    ],

                    'weights' => [
                        /** 
                         * Base penalty for missing Referer header.
                         */
                        'no_referer'   => 35,

                        /**
                         * Penalty for Referer header containing technical ports.
                         */
                        'port_leak'    => 45,

                        /**
                         * Penalty for suspicious loops where Referer equals Current URL.
                         */
                        'referer_loop' => 50,
                    ],
                  
                ],
            ],

            /**
             * Behavioral & Traffic Pattern Analysis
             * * The most resource-intensive analyzer. It examines the frequency 
             * of requests, navigation speed between pages, and detects 
             * suspicious "single-page" scanning patterns.
             */
            'behavioral' => [
                'enabled' => true,
                'class'   => \Oleant\VisitAnalytics\Analyzers\BehaviorAnalyzer::class,
                'params'  => [

                    /**
                     * Rate Limiting (Frequency)
                     * 'time_window' is the period in minutes to calculate the rate.
                     */
                    'time_window'           => 5,  // Minutes
                    'rate_limit_per_minute' => 60, // Max allowed requests per minute
                    'ua_stability_window'   => 30, // Minutes


                    /**
                     * Speed & Navigation Flow
                     * 'min_interval' is the humanly possible minimum seconds between clicks.
                     */
                    'min_interval_ms' => 250,

                    /**
                     * Visit Depth Analysis
                     * Identifies IPs that hit one page and never show activity again 
                     * within the specified window (useful for catching simple scanners).
                     */
                    'depth_check_window' => 60, // Minutes to look forward/backward

                    /**
                     * Cumulative Scoring logic
                     * Used when the bot breaks the referer chain but continues to browse.
                     */
                    'cumulative' => [
                        'no_referer_increment' => 20,
                    ],

                    'weights' => [
                        'single_visit'      => 15, // Score for "hit and run" behavior
                        'rate'              => 30, // Score for exceeding rate limit
                        'speed_anomaly'     => 20, // Score for inhumanly fast clicks
                        'ua_change_anomaly' => 40, // Score for change UA 
                    ],
                ],
            ],

            /**
             * Network & Infrastructure Analysis
             * * Performs Reverse DNS (PTR) lookups to identify the network owner.
             * Detects traffic originating from Datacenters and Cloud Providers,
             * which is a high-confidence indicator of automated activity.
             */
            'network' => [
                'enabled' => true,
                'class'   => \Oleant\VisitAnalytics\Analyzers\NetworkAnalyzer::class,
                'params'  => [

                    /**
                     * Datacenter Keyword Detection
                     * If the PTR record contains any of these keywords, the IP 
                     * is flagged as belonging to a hosting/cloud provider.
                     */
                    'datacenter_check' => [
                        'keywords' => [
                            'amazon', 'aws', 'google', 'cloud', 'azure', 'hetzner', 
                            'ovh', 'digitalocean', 'linode', 'vultr', 'server', 
                            'hosting', 'datacenter', 'dedicated', 'fastly', 
                            'akamai', 'leaseweb', 'softlayer', 'contabo', 'singlehop', 'internap'
                        ],
                    ],

                    'weights' => [
                        /**
                         * Penalty for IP addresses identified as Datacenters.
                         * Usually 100 as human traffic rarely comes from these networks.
                         */
                        'datacenter'    => 100,

                        /**
                         * Penalty for IPs with no Reverse DNS record.
                         * While not always a bot, missing PTR is common for 
                         * malicious scanning infrastructure.
                         */
                        'no_dns_record' => 50,
                    ],
                ],
            ],

            /**
             * IP Reputation & Historical Analysis
             * * Evaluates the "trust level" of an IP based on its past behavior.
             * If the IP has been flagged as a bot in the recent past, it receives
             * an automatic penalty, making it easier to re-detect persistent threats.
             */
            'reputation' => [
                'enabled' => true,
                'class'   => \Oleant\VisitAnalytics\Analyzers\ReputationAnalyzer::class,
                'params'  => [

                    /**
                     * Cumulative History Settings
                     */
                    'cumulative' => [
                        'enabled'               => true,
                        'history_window_hours'  => 24, // Look back period
                        'penalty_multiplier'    => 15, // Points per previous 'is_bot' event
                    ],
                ],
            ],

            /**
             * Botnet Cluster Detection
             * * Identifies distributed botnets by detecting multiple IPs 
             * * sharing the same HTTP fingerprint within a short time window.
             * * Redis-based, stateless and GDPR-compliant (no long-term tracking).
             */
            'botnet' => [
                'enabled' => true,
                'class'   => \Oleant\VisitAnalytics\Analyzers\BotnetAnalyzer::class, // Переименованный класс
                'params'  => [
                    
                    // --- Cluster Identification Thresholds ---
                    
                    /**
                     * Minimum number of unique IPs sharing the same Fingerprint 
                     * to trigger a botnet cluster flag.
                     */
                    'ip_cluster_threshold' => (int) env('VISIT_ANALYTICS_BOTNET_IP_THRESHOLD', 5),

                    /**
                     * Time-to-live for Redis fingerprint records (seconds).
                     * Defines how long we remember a fingerprint's association 
                     * with a specific IP cluster.
                     */
                    'redis_ttl' => (int) env('VISIT_ANALYTICS_BOTNET_REDIS_TTL', 3600),

                    /**
                     * The analysis window in minutes for the periodic analyzer.
                     * (e.g., 10 minutes matches your cron frequency).
                     */
                    'analysis_window_minutes' => (int) env('VISIT_ANALYTICS_BOTNET_WINDOW_MIN', 10),

                    // --- Performance & Safety ---

                    /**
                     * List of official bots/crawlers (IP ranges or UA patterns)
                     * that are exempted from the cluster detection logic.
                     */
                    'whitelist_patterns' => fn() => config('visit-analytics.detection_engine.analyzers.explicit_bots.params.explicit_bots', []),

                    'weights' => [
                        /**
                         * Penalty added to bot_score when a Fingerprint is 
                         * linked to multiple different IP addresses.
                         */
                        'cluster_anomaly_weight' => 100,
                    ],
                ],
            ],
        ],
    ],

    /**
     * Retroactive Analysis Settings
     * * This engine runs asynchronously (via cron) to identify bots that 
     * cannot be detected in a single request, but reveal themselves 
     * through behavioral patterns over a short period.
     */
    'retro_analysis' => [

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
    ],

];