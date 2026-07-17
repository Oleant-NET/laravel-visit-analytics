<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Analyzers;

use Oleant\VisitAnalytics\Analyzers\UserAgentAnalyzer;
use Oleant\VisitAnalytics\Analyzers\Rules\UserAgent\MissingUserAgentRule;
use Oleant\VisitAnalytics\Analyzers\Rules\UserAgent\BrowserEngineRule;
use Oleant\VisitAnalytics\Analyzers\Rules\UserAgent\PatternVerificationRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

/**
 * Helper to get the list of active rules for the UserAgentAnalyzer.
 */
function getRules(): array {
    return [
        MissingUserAgentRule::class,
        BrowserEngineRule::class,
        PatternVerificationRule::class,
    ];
}

it('penalizes empty user agent strings', function () {
    $log = VisitLog::factory()->make(['user_agent' => '']);
    $state = new AnalysisState();
    $analyzer = new UserAgentAnalyzer();
    
    $params = [
        'rules' => getRules(),
        'weights' => ['missing_ua' => 100]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(100)
        ->and($state->getReasons())->toContain('missing_user_agent')
        ->and($state->getEvidence())->toHaveKey('missing_user_agent.ua_status', 'empty_header');
});

it('detects suspicious keywords in user agent', function () {
    $log = VisitLog::factory()->make(['user_agent' => 'GuzzleHttp/7.0']);
    $state = new AnalysisState();
    $analyzer = new UserAgentAnalyzer();
    
    $params = [
        'rules' => getRules(),
        'browser_engines' => ['Gecko', 'WebKit'], 
        'weights' => ['ua_suspicious' => 50]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(50)
        ->and($state->getReasons())->toContain('ua_suspicious')
        ->and($state->getEvidence())->toHaveKey('ua_suspicious.reason', 'missing_browser_engine');
});

it('matches user agent regex patterns', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1)'
    ]);

    $state = new AnalysisState();
    $analyzer = new UserAgentAnalyzer();
    
    $params = [
        'rules' => getRules(),
        'browser_engines' => ['Googlebot'], 
        'ua_regex_patterns' => [
            'google_bot' => [
                'pattern' => 'Googlebot',
                'weight' => 40
            ]
        ]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('ua_match_google_bot')
        ->and($state->getScore())->toBe(40)
        ->and($state->getEvidence())->toHaveKey('ua_match_google_bot.matched_pattern', 'Googlebot');
});

it('flags modern chromium without client hints', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 ... Chrome/110.0.0.0 Safari/537.36',
        'target_headers' => [] 
    ]);

    $state = new AnalysisState();
    $analyzer = new UserAgentAnalyzer();
    
    $params = [
        'rules' => getRules(),
        'browser_engines' => ['Safari'],
        'ua_regex_patterns' => [
            'chrome' => ['pattern' => 'Chrome', 'requires_verification' => true]
        ],
        'weights' => ['verification_failed' => 80]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(80)
        ->and($state->getReasons())->toContain('verification_failed_chrome')
        ->and($state->getEvidence())->toHaveKey('verification_failed_chrome.check', 'client_hints_mismatch');
});

it('flags mismatch between UA platform and client hints', function () {
    // 1. Ensure the UA string contains a token that matches your os_mapping key
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0) Chrome/110.0.0.0 Safari/537.36',
        'target_headers' => [
            'sec-ch-ua' => '"Google Chrome";v="110"',
            'sec-ch-ua-platform' => '"Linux"' 
        ]
    ]);

    $state = new AnalysisState();
    $analyzer = new UserAgentAnalyzer();
    
    $params = [
        'rules' => getRules(),
        'browser_engines' => ['Safari'],
        'ua_regex_patterns' => [
            'chrome' => ['pattern' => 'Chrome', 'requires_verification' => true]
        ],
        // 2. The key 'Windows' now matches the UA string above
        'os_mapping' => ['Windows' => 'Windows'], 
        'weights' => ['verification_failed' => 80]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('verification_failed_chrome')
        ->and($state->getScore())->toBe(80)
        ->and($state->getEvidence())->toHaveKey('verification_failed_chrome.check', 'client_hints_mismatch');
});

it('accepts consistent user agent and client hints', function () {
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 ... Chrome/110.0.0.0 Safari/537.36',
        'target_headers' => [
            'sec-ch-ua' => '"Google Chrome";v="110"',
            'sec-ch-ua-platform' => '"Windows"'
        ]
    ]);

    $state = new AnalysisState();
    $analyzer = new UserAgentAnalyzer();
    
    $params = [
        'rules' => getRules(),
        'browser_engines' => ['Safari'],
        'ua_regex_patterns' => [
            'chrome' => ['pattern' => 'Chrome', 'requires_verification' => true]
        ],
        'os_mapping' => ['Windows' => 'Windows']
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(0);
});