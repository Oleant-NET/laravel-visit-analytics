<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Analyzers;

use Oleant\VisitAnalytics\Analyzers\BehaviorAnalyzer;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;

// ВАЖНО: Привязываем тесты к вашему TestCase, чтобы Faker инициализировался корректно
uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

const TEST_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

function getBaseParams(): array
{
    return [
        'weights' => [
            'single_visit' => 0,
            'rate' => 0,
            'speed_anomaly' => 0,
            'ua_change_anomaly' => 0,
        ],
        'cumulative' => [
            'no_referer_increment' => 0,
        ],
        'depth_check_window' => 60,
        'time_window' => 5,
        'rate_limit_per_minute' => 120,
        'min_interval_ms' => 250,
        'ua_stability_window' => 30,
    ];
}

test('it flags single page scans when no other visits are found', function () {
    $log = VisitLog::factory()->create([
        'ip_address' => '1.1.1.1',
        'referer' => null,
        'user_agent' => TEST_UA
    ]);

    $state = new AnalysisState();
    $analyzer = new BehaviorAnalyzer();

    $params = getBaseParams();
    $params['weights']['single_visit'] = 5;

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('single_page_scan')
        ->and($state->getScore())->toBe(5);
});

test('it flags high request rates based on time window', function () {
    $ip = '2.2.2.2';
    
    VisitLog::factory()->count(10)->create([
        'ip_address' => $ip,
        'created_at' => now()->subSeconds(10),
        'target_headers' => null
    ]);

    $log = VisitLog::factory()->create([
        'ip_address' => $ip, 
        'created_at' => now(),
        'target_headers' => null
    ]);

    $state = new AnalysisState();
    $analyzer = new BehaviorAnalyzer();

    $params = getBaseParams();
    $params['weights']['rate'] = 15;
    $params['rate_limit_per_minute'] = 1;
    $params['time_window'] = 5;

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('high_request_rate')
        ->and($state->getScore())->toBe(15);
});

test('it detects repeated ultra fast navigation anomalies', function () {
    $ip = '3.3.3.3';
    $now = now()->micro(0);
    Carbon::setTestNow($now);

    VisitLog::factory()->create([
        'ip_address' => $ip,
        'created_at' => $now->copy()->subSeconds(1),
        'bot_reasons' => ['speed_anomaly'], 
        'user_agent' => TEST_UA
    ]);

    $log = VisitLog::factory()->create([
        'ip_address' => $ip, 
        'created_at' => $now,
        'user_agent' => TEST_UA
    ]);

    $state = new AnalysisState();
    $analyzer = new BehaviorAnalyzer();

    $params = getBaseParams();
    $params['weights']['speed_anomaly'] = 40;
    $params['min_interval_ms'] = 2000;

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('speed_anomaly')
        ->and($state->getScore())->toBe(40);
    
    Carbon::setTestNow();
});

test('it detects user agent change anomaly', function () {
    $ip = '4.4.4.4';
    VisitLog::factory()->create([
        'ip_address' => $ip, 
        'user_agent' => 'Browser A', 
        'created_at' => now()->subMinutes(5)
    ]);
    
    $log = VisitLog::factory()->create([
        'ip_address' => $ip, 
        'user_agent' => 'Browser B',
        'created_at' => now()
    ]);

    $state = new AnalysisState();
    $analyzer = new BehaviorAnalyzer();

    $params = getBaseParams();
    $params['weights']['ua_change_anomaly'] = 50;
    $params['ua_stability_window'] = 30;

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('ua_change_anomaly')
        ->and($state->getScore())->toBe(50);
});

test('it flags broken referer chain', function () {
    $ip = '5.5.5.5';
    VisitLog::factory()->create([
        'ip_address' => $ip,
        'url' => 'https://site.com/p1',
        'created_at' => now()->subMinutes(1)
    ]);

    $log = VisitLog::factory()->create([
        'ip_address' => $ip,
        'url' => 'https://site.com/p2',
        'referer' => null,
        'target_headers' => ['sec-fetch-site' => 'same-origin'],
    ]);

    $state = new AnalysisState();
    $analyzer = new BehaviorAnalyzer();

    $params = getBaseParams();
    $params['cumulative']['no_referer_increment'] = 20;

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('broken_referer_chain')
        ->and($state->getScore())->toBe(20);
});

test('it does not flag normal AJAX requests', function () {
    $ip = '6.6.6.6';
    $log = VisitLog::factory()->create([
        'ip_address' => $ip,
        'target_headers' => ['x-requested-with' => 'XMLHttpRequest']
    ]);

    $state = new AnalysisState();
    $analyzer = new BehaviorAnalyzer();

    $params = getBaseParams();
    $params['weights']['speed_anomaly'] = 40;

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(0)
        ->and($state->getReasons())->not->toContain('speed_anomaly');
});