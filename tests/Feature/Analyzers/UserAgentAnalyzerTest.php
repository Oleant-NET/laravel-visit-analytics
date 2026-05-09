<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Analyzers;

use Oleant\VisitAnalytics\Analyzers\UserAgentAnalyzer;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

/**
 * @test
 * Verifies that an empty User-Agent results in a critical penalty.
 */
it('penalizes empty user agent strings', function () {
    $log = VisitLog::factory()->make(['user_agent' => '']);
    $state = new AnalysisState();
    $analyzer = new UserAgentAnalyzer();
    
    $params = ['weights' => ['missing_ua' => 100]];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(100)
        ->and($state->getReasons())->toContain('missing_user_agent');
});

/**
 * @test
 * Checks for suspicious library or automation tool keywords within the UA string.
 */
it('detects suspicious keywords in user agent', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'GuzzleHttp/7.0'
    ]);

    $state = new AnalysisState();
    $analyzer = new UserAgentAnalyzer();
    
    $params = [
        'suspicious_ua' => ['GuzzleHttp', 'python-requests'],
        'weights' => ['ua_suspicious' => 50]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(50)
        ->and($state->getEvidence())->toHaveKey('ua_match_keyword', 'GuzzleHttp');
});

/**
 * @test
 * Verifies regex pattern matching for specific browser or bot signatures.
 */
it('matches user agent regex patterns', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    ]);

    $state = new AnalysisState();
    $analyzer = new UserAgentAnalyzer();
    
    $params = [
        'ua_regex_patterns' => [
            'google_bot' => [
                'pattern' => 'Googlebot',
                'weight' => 40
            ]
        ]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('ua_match_google_bot')
        ->and($state->getScore())->toBe(40);
});

/**
 * @test
 * Ensures Chromium browsers (v100+) are flagged if they fail to provide Client Hints.
 */
it('flags modern chromium without client hints', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
        'target_headers' => [] // Missing sec-ch-ua
    ]);

    $state = new AnalysisState();
    $analyzer = new UserAgentAnalyzer();
    
    $params = [
        'ua_regex_patterns' => [
            'chrome' => [
                'pattern' => 'Chrome',
                'requires_verification' => true
            ]
        ],
        'weights' => ['verification_failed' => 80]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(80)
        ->and($state->getReasons())->toContain('verification_failed_chrome');
});

/**
 * @test
 * Verifies that mismatched OS information between UA and Client Hints triggers a penalty.
 */
it('flags mismatch between UA platform and client hints', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
        'target_headers' => [
            'sec-ch-ua' => '"Google Chrome";v="110"',
            'sec-ch-ua-platform' => '"Linux"' // Mismatch: UA contains 'Windows', but hint says 'Linux'
        ]
    ]);

    $state = new AnalysisState();
    $analyzer = new UserAgentAnalyzer();
    
    $params = [
        'ua_regex_patterns' => [
            'chrome' => ['pattern' => 'Chrome', 'requires_verification' => true]
        ],
        'os_mapping' => [
            'Windows' => 'Windows'
        ],
        'weights' => ['verification_failed' => 80]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('verification_failed_chrome')
        ->and($state->getScore())->toBe(80);
});

/**
 * @test
 * Ensures a perfectly consistent User-Agent and Client Hint pair results in no penalty.
 */
it('accepts consistent user agent and client hints', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
        'target_headers' => [
            'sec-ch-ua' => '"Google Chrome";v="110"',
            'sec-ch-ua-platform' => '"Windows"'
        ]
    ]);

    $state = new AnalysisState();
    $analyzer = new UserAgentAnalyzer();
    
    $params = [
        'ua_regex_patterns' => [
            'chrome' => ['pattern' => 'Chrome', 'requires_verification' => true]
        ],
        'os_mapping' => ['Windows' => 'Windows']
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(0);
});