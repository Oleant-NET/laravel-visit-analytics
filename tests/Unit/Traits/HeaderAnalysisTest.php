<?php

use Oleant\VisitAnalytics\Traits\HeaderAnalysis;
use Oleant\VisitAnalytics\Support\AnalysisState;

class HeaderAnalysisMock
{
    use HeaderAnalysis {
        evaluateHeaderDiversity as public;
        evaluateHeaderWeights as public;
        analyzeConsistency as public;
    }
}

it('detects low header diversity', function () {
    $mock = new HeaderAnalysisMock();
    $state = new AnalysisState();
    
    $headers = ['host' => 'test.com', 'user-agent' => 'bot']; // Count: 2
    $params = ['min_total_headers' => 5, 'score' => 40];

    $mock->evaluateHeaderDiversity($headers, $state, $params);

    expect($state->getReasons())->toContain('suspicious_minimal_headers')
        ->and($state->getScore())->toBe(40);
});

it('validates mandatory headers and skips non-chromium client hints', function () {
    $mock = new HeaderAnalysisMock();
    $state = new AnalysisState();
    
    $headers = []; 
    $userAgent = 'Mozilla/5.0 (Firefox/110.0)';
    $scores = ['host' => 10, 'sec-ch-ua-platform' => 50];

    $mock->evaluateHeaderWeights($headers, $userAgent, $state, $scores);

    expect($state->getReasons())->toContain('missing_mandatory_header_host')
        ->and($state->getReasons())->not->toContain('missing_mandatory_header_sec-ch-ua-platform');
});

it('detects OS mismatch between user-agent and client hints', function () {
    $mock = new HeaderAnalysisMock();
    $state = new AnalysisState();
    
    $headers = ['sec-ch-ua-platform' => '"macOS"'];
    $userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';
    $params = ['os_platform_mismatch_score' => 60];

    $mock->analyzeConsistency($headers, $userAgent, $state, $params);

    expect($state->getReasons())->toContain('fingerprint_mismatch')
        ->and($state->getScore())->toBe(60);
});

it('flags over-engineered requests without cookies', function () {
    $mock = new HeaderAnalysisMock();
    $state = new AnalysisState();
    
    // No cookie, but has arch header -> should trigger 'bot_over_engineered'
    $headers = ['sec-ch-ua-arch' => '"arm"'];
    $userAgent = 'Chrome/120.0.0.0';
    $params = [
        'high_entropy' => ['headers' => ['sec-ch-ua-full-version-list'], 'score' => 20],
        'arch_architecture_mismatch_score' => 30
    ];

    $mock->analyzeConsistency($headers, $userAgent, $state, $params);

    expect($state->getReasons())->toContain('bot_over_engineered');
});