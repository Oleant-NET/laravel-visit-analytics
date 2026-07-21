<?php

return [
    'enabled'   => true,
    
    'threshold' => 70, // Total score to flag a visit as a bot

    /**
     * Bot Analysis Rules
     * 
     * Each rule must implement the RuleInterface.
     * The engine iterates through enabled rules and aggregates their scores.
     * ...
     *     group_of_analysis => [class_of_rule => array_of_params]
     */
    'rules' => [
        'explicit_bots' => [
            \Oleant\VisitAnalytics\Rules\ExplicitBots\ExplicitBotsRule::class => [
                'signatures' => [
                    'bot', '+http', 'baiduspider', 'ia_archiver',
                ],
                'score' => 100,
            ],
        ],

        'header_integrity' => [
            \Oleant\VisitAnalytics\Rules\HeaderIntegrity\HeaderDiversityRule::class => [
                'min_total_headers' => 5,
                'score' => 30,
            ],
            \Oleant\VisitAnalytics\Rules\HeaderIntegrity\HeaderWeightsRule::class => [
                'scores_without' => [
                    'accept-language'      => 15,
                    'accept-encoding'      => 10,
                    'sec-fetch-dest'       => 5,
                    'sec-fetch-site'       => 5,
                    'sec-fetch-mode'       => 5,
                    'sec-ch-ua'            => 15,
                    'sec-ch-ua-platform'   => 5,
                    'sec-ch-ua-mobile'     => 5,
                ],                ],
            \Oleant\VisitAnalytics\Rules\HeaderIntegrity\HeaderConsistencyRule::class => [
                'high_entropy' => [
                    'headers' => [
                        'sec-ch-ua-platform-version',
                        'sec-ch-ua-full-version-list',
                        'sec-ch-ua-model',
                    ],
                    'score'   => 20,
                ],
                'os_platform_mismatch_score' => 50,
                'arch_architecture_mismatch_score' => 25,
            ],
            \Oleant\VisitAnalytics\Rules\HeaderIntegrity\HeaderSetStabilityRule::class => [
                'header_stability_window' => 30, // Minutes
                'exclude_dynamic_headers' => [
                    'sec-fetch-dest',
                    'sec-fetch-mode',
                    'sec-fetch-site',
                    'x-requested-with',
                ],
                'score' => 30,
            ],
        ],

        'user_agent' => [
            \Oleant\VisitAnalytics\Rules\UserAgent\BrowserEngineRule::class => [
                'browser_engines' => [
                    'AppleWebKit', 'Gecko', 'Trident', 'Blink', 'KHTML', 'Presto', 'Goanna',  'Servo',
                ],
                'score' => 50,

            ],
            \Oleant\VisitAnalytics\Rules\UserAgent\MissingUserAgentRule::class => [
                'score' => 100,
            ],
            \Oleant\VisitAnalytics\Rules\UserAgent\PatternVerificationRule::class => [
                'ua_regex_patterns' => [
                    'reduced_ua' => [
                        'pattern' => '/\d+\.0\.0\.0/', 
                        'score'  => 20,
                        'requires_verification' => true,
                    ],
                    'headless_chrome' => [
                        'pattern' => '/HeadlessChrome/i',
                        'score'  => 100,
                        'requires_verification' => false,
                    ],
                ],
            ],
            \Oleant\VisitAnalytics\Rules\UserAgent\UserAgentStabilityRule::class => [
                'ua_stability_window' => 30, // Minutes
                'score'               => 40, // Score for change UA 
            ],
        ],

        /**
         * Obsolete Operating System Detection
         */
        'obsolete_os' => [
            \Oleant\VisitAnalytics\Rules\ObsoleteOS\ObsoleteOSRule::class => [
                'target_os' => [
                    'Windows 95', 'Win95', 'Windows 98', 'Win98', 'Windows ME', 'Windows NT 5.', 'Windows NT 6.0',  'Windows NT 6.1',  'Windows NT 6.2',  'Windows NT 6.3', 'Mac OS X 10', 'Android 4.', 'Android 5.', 'Android 6.',
                ],
                'score' => 35,
            ],
            \Oleant\VisitAnalytics\Rules\ObsoleteOS\ObsoleteBrowserRule::class => [
                'target_browsers' => [
                    'MSIE', 'Trident/', 'Opera/8', 'Opera/9',
                ],
                'score' => 35,
            ],
        ],

        /*
        * Outdated Browser Detection Settings
        */
        'outdated_browser' => [
            \Oleant\VisitAnalytics\Rules\OutdatedBrowser\OutdatedBrowserRule::class => [
                'current_versions' => [
                    'chrome'  => 147,
                    'firefox' => 150,
                    'safari'  => 19,
                    'edge'    => 147,
                    'opera'   => 131,
                    'ie'      => 11,
                ],
                'scoring' => [
                    'minor_lag' => [
                        'diff'        => 5,
                        'score'       => 10,
                    ],
                    'moderate_lag' => [
                        'diff'        => 10,
                        'score'       => 25,
                    ],
                    'ancient_lag' => [
                        'diff'        => 20,
                        'score'       => 50,
                    ],
                ],
            ],
        ],

        /**
         * Honeypot Trap Rules
         */
        'honeypots' => [
            \Oleant\VisitAnalytics\Rules\Honeypot\HoneypotRule::class => [
                'honeypot_paths' => [
                    '/.env', '/.git', '/wp-admin',
                    '/wp-login', '/bitrix', '/config.php',
                    '/composer.lock', '/phpinfo.php', '/.aws/credentials', '/.vscode/sftp.json', '/actuator/health',
                ],
                'score' => 100,
            ],    
        ],

        /**
         * Referer Integrity & Navigation Analysis
         */
        'referer' => [
            \Oleant\VisitAnalytics\Rules\Referer\MissingRefererRule::class => [
                'cumulative' => [
                    'no_referer_window_minutes' => 10,
                    'no_referer_increment'      => 20, // Extra points per repeated hit
                ],
                'score' => 35,
            ],
            \Oleant\VisitAnalytics\Rules\Referer\PortLeakRule::class => [
                'port_leak' => [
                    2082, 2083, // cPanel
                    2086, 2087, // WHM
                    8443, 8880, // Plesk
                    2222,       // DirectAdmin
                    10000,      // Webmin
                    8888,       // Common proxy/dev port
                ],
                'score' => 45,
            ],
            \Oleant\VisitAnalytics\Rules\Referer\SelfRefererRule::class => [
                'score' => 50,
            ],
            \Oleant\VisitAnalytics\Rules\Referer\RefererChainRule::class => [
                'score' => 20,
            ],
            \Oleant\VisitAnalytics\Rules\Referer\RefererLoopRule::class => [
                'referer_loop_threshold' => 3,
                'score'                  => 10,  // Score for self-referencing loops
            ],
        ],

        /**
         * Behavioral & Traffic Pattern Analysis
         */
        'behavioral' => [
            \Oleant\VisitAnalytics\Rules\Behavioral\VisitDepthRule::class => [
                'depth_check_window' => 60, // Minutes to look forward/backward
                'score'              => 15,
            ],
            \Oleant\VisitAnalytics\Rules\Behavioral\RateLimitRule::class => [
                'time_window'           => 5,  // Minutes
                'rate_limit_per_minute' => 60, // Max allowed requests per minute
                'score'                  => 30, // Score for exceeding rate limit
            ],
            \Oleant\VisitAnalytics\Rules\Behavioral\SuspiciousEntryRule::class => [
                'suspicious_entry'  => 100, // Score for suspicious Entry
            ],
            \Oleant\VisitAnalytics\Rules\Behavioral\SpeedAnomalyRule::class => [
                'min_interval_ms' => 250,
                'score'           => 20, // Score for inhumanly fast clicks
            ],
        ],

        /**
         * Network & Infrastructure Analysis
         */
        'network' => [
            \Oleant\VisitAnalytics\Rules\Network\NetworkPtrRule::class => [
                'score' => 50,
            ],
            \Oleant\VisitAnalytics\Rules\Network\NetworkDatacenterRule::class => [
                'datacenter_keywords' => [
                    'amazon', 'aws', 'google', 'cloud', 'azure', 'hetzner', 
                    'ovh', 'digitalocean', 'linode', 'vultr', 'server', 
                    'hosting', 'datacenter', 'dedicated', 'fastly', 
                    'akamai', 'leaseweb', 'softlayer', 'contabo', 'singlehop', 'internap'
                ],
                'score'    => 100,
            ],
        ],

        /**
         * IP Reputation & Historical Analysis
         */
        'reputation' => [
            \Oleant\VisitAnalytics\Rules\Reputation\RepeatOffenderRule::class => [
                'history_window_hours' => 24, // Look back period
                'score'                => 15, // Points per previous 'is_bot' event
            ],
        ],

        /**
         * Botnet Cluster Detection
         */
        'botnet' => [
            \Oleant\VisitAnalytics\Rules\Botnet\BotnetRule::class => [
                'analysis_window_minutes' => 10,
                'ip_cluster_threshold'    => 5,
                'whitelist_patterns'      => [
                    'bot', '+http', 'spider', 'archiver',
                ],
                'score'                   => 100,
            ],
        ],
    ],
];