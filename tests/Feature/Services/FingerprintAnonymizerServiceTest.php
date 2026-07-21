<?php

use Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Services\FingerprintAnonymizerService;

uses(TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    Config::set('visit-analytics-collection.anonymization', [
        'anonymize_ua' => true,
        'anonymize_headers' => true,
        'anonymize_fingerprint_hash' => true,
        'fingerprint_placeholder' => 'anonym-sha256-ready',
        'anonymize_bots' => true,
    ]);
});

/**
 * BOT HANDLING
 */

it('returns bot label for non-official bots', function () {
    $log = VisitLog::factory()->make([
        'is_bot' => true,
        'is_official_bot' => false,
        'user_agent' => 'SomeBot',
        'target_headers' => [],
    ]);

    $service = new FingerprintAnonymizerService();

    expect($service->handle($log)['user_agent'])->toBe('Bot UA');
});

it('returns legal bot label for official bots', function () {
    $log = VisitLog::factory()->make([
        'is_bot' => true,
        'is_official_bot' => true,
        'user_agent' => 'Googlebot',
        'target_headers' => [],
    ]);

    $service = new FingerprintAnonymizerService();

    expect($service->handle($log)['user_agent'])->toBe('Legal Bot UA');
});

/**
 * USER AGENT
 */

it('anonymizes user agent using client hints headers', function () {
    $log = VisitLog::factory()->make([
        'is_bot' => false,
        'user_agent' => 'Mozilla',
        'target_headers' => [
            'sec-ch-ua-platform' => '"Windows"',
            'sec-ch-ua' => '"Chrome";v="120", "Not)A;Brand";v="99"',
            'sec-ch-ua-mobile' => '?0',
        ],
    ]);

    $service = new FingerprintAnonymizerService();

    $result = $service->handle($log);

    expect($result['user_agent'])
        ->toContain('Chrome')
        ->toContain('Windows')
        ->toContain('Desktop');
});

it('parses legacy user agent string', function () {
    $log = VisitLog::factory()->make([
        'is_bot' => false,
        'user_agent' => 'Mozilla/5.0 Windows NT Chrome Safari',
        'target_headers' => [],
    ]);

    $service = new FingerprintAnonymizerService();

    expect($service->handle($log)['user_agent'])
        ->toContain('Chrome')
        ->toContain('Windows');
});

it('skips user agent anonymization when disabled', function () {
    Config::set('visit-analytics-collection.anonymization.anonymize_ua', false);

    $log = VisitLog::factory()->make([
        'user_agent' => 'Mozilla/5.0 Windows NT Chrome',
        'target_headers' => [],
    ]);

    $service = new FingerprintAnonymizerService();

    expect($service->handle($log))->not->toHaveKey('user_agent');
});

/**
 * HEADERS
 */

it('reduces headers to keys only', function () {
    $log = VisitLog::factory()->make([
        'target_headers' => [
            'user-agent' => 'Chrome',
            'cookie' => 'abc123',
        ],
    ]);

    $service = new FingerprintAnonymizerService();

    expect($service->handle($log)['target_headers'])
        ->toBe(['user-agent', 'cookie']);
});

it('returns null for empty headers', function () {
    $log = VisitLog::factory()->make([
        'target_headers' => [],
    ]);

    $service = new FingerprintAnonymizerService();

    expect($service->handle($log)['target_headers'])->toBeNull();
});

/**
 * FINGERPRINT
 */

it('replaces fingerprint hash with placeholder', function () {
    $log = VisitLog::factory()->make([
        'fingerprint_hash' => 'abc123',
    ]);

    $service = new FingerprintAnonymizerService();

    expect($service->handle($log)['fingerprint_hash'])
        ->toBe('anonym-sha256-ready');
});

it('keeps fingerprint hash when disabled', function () {
    Config::set('visit-analytics-collection.anonymization.anonymize_fingerprint_hash', false);

    $log = VisitLog::factory()->make([
        'fingerprint_hash' => 'abc123',
    ]);

    $service = new FingerprintAnonymizerService();

    expect($service->handle($log))->not->toHaveKey('fingerprint_hash');
});