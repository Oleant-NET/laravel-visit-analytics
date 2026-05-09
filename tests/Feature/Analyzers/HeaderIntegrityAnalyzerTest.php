<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Analyzers;

use Oleant\VisitAnalytics\Analyzers\HeaderIntegrityAnalyzer;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

/**
 * @test
 */
it('skips analysis when disabled in config', function () {
    $log = VisitLog::factory()->make(['target_headers' => []]);
    $state = new AnalysisState();
    $analyzer = new HeaderIntegrityAnalyzer();
    
    $analyzer->analyze($log, $state, ['enabled' => false]);

    expect($state->getScore())->toBe(0);
});

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
        'enabled' => true,
        'min_total_headers' => ['count' => 1],
        'target_headers' => ['cookie']
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getEvidence())->toHaveKey('cookie_missing_in_headers', true);
});