<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Analyzers;

use Oleant\VisitAnalytics\Analyzers\HeaderIntegrityAnalyzer;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

/**
 * @test
 */
it('flags requests with very few headers', function () {
    $log = VisitLog::factory()->make([
        'target_headers' => [
            'host' => 'localhost',
            'user-agent' => 'some-agent'
        ]
    ]);

    $state = new AnalysisState();
    $analyzer = new HeaderIntegrityAnalyzer();
    
    $params = [
        'rules' => [
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderDiversityRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderCookieRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderConsistencyRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderWeightsRule::class,
        ],
        'enabled' => true,
        'min_total_headers' => ['count' => 5, 'score' => 40],
        'weights' => [] // Отключаем проверку весов
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('suspicious_minimal_headers')
        ->and($state->getScore())->toBe(40);
});

/**
 * @test
 */
it('penalizes missing mandatory headers', function () {
    $log = VisitLog::factory()->make([
        'target_headers' => [
            'host' => 'localhost',
            'user-agent' => 'Mozilla/5.0...',
            'connection' => 'keep-alive',
            'accept-encoding' => 'gzip',
            'accept-language' => 'en-US',
            'referer' => 'https://google.com' // Добавили, чтобы не было штрафа за реферер
        ]
    ]);

    $state = new AnalysisState();
    $analyzer = new HeaderIntegrityAnalyzer();
    
    $params = [
        'rules' => [
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderDiversityRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderCookieRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderConsistencyRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderWeightsRule::class,
        ],
        'enabled' => true,
        'min_total_headers' => ['count' => 1], // Занижаем лимит, чтобы не мешал
        'weights' => [
            'accept' => 25,
            'referer' => 10
        ]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('missing_mandatory_header_accept')
        ->and($state->getScore())->toBe(25); // Теперь будет ровно 25
});

/**
 * @test
 */
it('requires client hints only for chrome-based browsers', function () {
    $analyzer = new HeaderIntegrityAnalyzer();
    
    $params = [
        'rules' => [
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderDiversityRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderCookieRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderConsistencyRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderWeightsRule::class,
        ],
        'enabled' => true,
        'min_total_headers' => ['count' => 1], // Снижаем, чтобы Firefox не падал по количеству
        'weights' => ['sec-ch-ua' => 50]
    ];

    // 1. Case: Firefox
    $stateFirefox = new AnalysisState();
    $firefoxLog = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; rv:100.0) Gecko/20100101 Firefox/100.0',
        'target_headers' => ['host' => 'test.dev', 'accept' => '*/*'] 
    ]);
    $analyzer->analyze($firefoxLog, $stateFirefox, $params);
    expect($stateFirefox->getScore())->toBe(0);

    // 2. Case: Chrome
    $stateChrome = new AnalysisState();
    $chromeLog = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36',
        'target_headers' => ['host' => 'test.dev', 'accept' => '*/*'] 
    ]);
    $analyzer->analyze($chromeLog, $stateChrome, $params);
    expect($stateChrome->getReasons())->toContain('missing_mandatory_header_sec-ch-ua')
        ->and($stateChrome->getScore())->toBe(50);
});

/**
 * @test
 */
it('adds evidence when cookie header is missing and tracked', function () {
    $log = VisitLog::factory()->make([
        'target_headers' => ['host' => 'localhost']
    ]);

    $state = new AnalysisState();
    $analyzer = new HeaderIntegrityAnalyzer();
    
    $params = [
        'rules' => [
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderDiversityRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderCookieRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderConsistencyRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderWeightsRule::class,
        ],
        'enabled' => true,
        'min_total_headers' => ['count' => 1],
        'target_headers' => ['cookie']
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getEvidence())->toHaveKey('cookie_missing_in_headers', true);
});

/**
 * @test
 */
it('flags over-engineered bots sending high-entropy headers on cold start', function () {
    $analyzer = new HeaderIntegrityAnalyzer();
    $state = new AnalysisState();
    
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0',
        'target_headers' => ['sec-ch-ua-full-version-list' => '...']
    ]);

    $params = [
        'rules' => [
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderDiversityRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderCookieRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderConsistencyRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderWeightsRule::class,
        ],
        'min_total_headers' => ['count' => 1],
        'target_headers' => ['cookie'],
        'consistency_checks' => [
            'high_entropy' => [
                'enabled' => true,
                'score' => 35,
                'headers' => ['sec-ch-ua-full-version-list']
            ]
        ]
    ];

    $analyzer->analyze($log, $state, $params);
    expect($state->getReasons())->toContain('bot_over_engineered')
        ->and($state->getScore())->toBe(35);
});

/**
 * @test
 */
it('flags platform mismatch between UA and client hints', function () {
    $analyzer = new HeaderIntegrityAnalyzer();
    $state = new AnalysisState();
    
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0)', 
        'target_headers' => ['sec-ch-ua-platform' => 'macOS']
    ]);

    $params = [
        'rules' => [
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderDiversityRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderCookieRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderConsistencyRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderWeightsRule::class,
        ],
        'min_total_headers' => ['enabled' => false, 'count' => 0], 
        'consistency_checks' => [
            'os_platform_mismatch' => ['enabled' => true, 'score' => 50]
        ]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getEvidence())->toHaveKey('fingerprint_mismatch.reason', 'os_conflict')
        ->and($state->getScore())->toBe(50);
});

/**
 * @test
 */
it('flags mobile desktop conflict', function () {
    $analyzer = new HeaderIntegrityAnalyzer();
    $state = new AnalysisState();
    
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0)',
        'target_headers' => [
            'sec-ch-ua-platform' => 'Windows',
            'sec-ch-ua-mobile' => '?1'
        ]
    ]);

    $params = [
        'rules' => [
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderDiversityRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderCookieRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderConsistencyRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderWeightsRule::class,
        ],
        'min_total_headers' => ['count' => 0],
        'consistency_checks' => [
            'os_platform_mismatch' => ['enabled' => true, 'score' => 50]
        ]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getEvidence())->toHaveKey('fingerprint_mismatch.reason', 'mobile_desktop_conflict')
        ->and($state->getScore())->toBe(50);
});

/**
 * @test
 */
it('flags unsolicited architecture header on cold start', function () {
    $analyzer = new HeaderIntegrityAnalyzer();
    $state = new AnalysisState();
    
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0',
        'target_headers' => ['sec-ch-ua-arch' => 'arm64']
    ]);

    $params = [
        'rules' => [
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderDiversityRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderCookieRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderConsistencyRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderWeightsRule::class,
        ],
        'min_total_headers' => ['count' => 0],
        'consistency_checks' => [
            'arch_architecture_mismatch' => ['enabled' => true, 'score' => 20]
        ]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getEvidence())->toHaveKey('bot_over_engineered.reason', 'unsolicited_arch_header')
        ->and($state->getScore())->toBe(20);
});

/**
 * @test
 */
it('flags architecture conflict', function () {
    $analyzer = new HeaderIntegrityAnalyzer();
    $state = new AnalysisState();
    
    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)',
        'target_headers' => ['sec-ch-ua-arch' => 'arm64', 'cookie' => 'exists']
    ]);

    $params = [
        'rules' => [
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderDiversityRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderCookieRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderConsistencyRule::class,
            \Oleant\VisitAnalytics\Analyzers\Rules\HeaderIntegrity\HeaderWeightsRule::class,
        ],
        'min_total_headers' => ['count' => 0],
        'consistency_checks' => [
            'arch_architecture_mismatch' => ['enabled' => true, 'score' => 45]
        ]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getEvidence())->toHaveKey('fingerprint_mismatch.reason', 'arch_conflict')
        ->and($state->getScore())->toBe(45);
});