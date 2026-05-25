<?php

use Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Services\FullAnonymizerService;
use Oleant\VisitAnalytics\Services\IpAnonymizerService;
use Oleant\VisitAnalytics\Services\FingerprintAnonymizerService;

uses(TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    Config::set('visit-analytics.collection.anonymization', [
        'anonymize_retention_minutes' => 30,
        'anonymize_bots' => true,
        'anonymize_mode' => 'sync',
        'anonymize_ip' => true,
        'anonymize_ua' => true,
        'anonymize_headers' => true,
        'anonymize_fingerprint_hash' => true,
        'fingerprint_placeholder' => 'anonym-sha256-ready',
    ]);

    $this->service = new FullAnonymizerService(
        new IpAnonymizerService(),
        new FingerprintAnonymizerService()
    );
});

/**
 * -------------------------------------------------
 * BASIC BEHAVIOR
 * -------------------------------------------------
 */

it('does not anonymize fresh logs', function () {
    $log = VisitLog::factory()->create([
        'processed_at' => now(),
        'created_at' => now(),
        'anonymized_at' => null,
        'ip_address' => '1.2.3.4',
    ]);

    $count = $this->service->runDeferredAnonymization();

    expect($count)->toBe(0);

    expect($log->fresh()->ip_address)->toBe('1.2.3.4');
});

it('anonymizes logs older than retention window', function () {
    $log = VisitLog::factory()->create([
        'processed_at' => now(),
        'created_at' => now()->subMinutes(40),
        'anonymized_at' => null,
        'ip_address' => '192.168.1.15',
        'user_agent' => 'Mozilla',
        'target_headers' => [
            'cookie' => 'abc',
        ],
        'fingerprint_hash' => 'hash123',
    ]);

    $count = $this->service->runDeferredAnonymization();

    expect($count)->toBe(1);

    $log->refresh();

    expect($log->anonymized_at)->not->toBeNull();
    expect($log->ip_address)->toBe('192.168.1.0');
});

/**
 * -------------------------------------------------
 * RETENTION RULES
 * -------------------------------------------------
 */

it('skips logs inside retention window', function () {
    VisitLog::factory()->create([
        'processed_at' => now(),
        'created_at' => now()->subMinutes(10),
        'anonymized_at' => null,
    ]);

    $count = $this->service->runDeferredAnonymization();

    expect($count)->toBe(0);
});

/**
 * -------------------------------------------------
 * BOT FILTERING
 * -------------------------------------------------
 */

it('skips bot logs when anonymize_bots is disabled', function () {
    Config::set('visit-analytics.collection.anonymization.anonymize_bots', false);

    $log = VisitLog::factory()->create([
        'processed_at' => now(),
        'created_at' => now()->subMinutes(40),
        'anonymized_at' => null,
        'is_bot' => true,
        'ip_address' => '1.1.1.1',
    ]);

    $count = $this->service->runDeferredAnonymization();

    expect($count)->toBe(0);

    $log->refresh();

    expect($log->anonymized_at)->toBeNull()
        ->and($log->ip_address)->toBe('1.1.1.1');
});

/**
 * -------------------------------------------------
 * IP + FINGERPRINT INTEGRATION
 * -------------------------------------------------
 */

it('applies ip anonymization correctly', function () {
    $log = VisitLog::factory()->create([
        'processed_at' => now(),
        'created_at' => now()->subMinutes(40),
        'anonymized_at' => null,
        'ip_address' => '8.8.8.8',
    ]);

    $this->service->runDeferredAnonymization();

    expect($log->fresh()->ip_address)->toBe('8.8.8.0');
});

it('applies fingerprint anonymization correctly', function () {
    $log = VisitLog::factory()->create([
        'processed_at' => now(),
        'created_at' => now()->subMinutes(40),
        'anonymized_at' => null,
        'fingerprint_hash' => 'abc123',
    ]);

    $this->service->runDeferredAnonymization();

    expect($log->fresh()->fingerprint_hash)->toBe('anonym-sha256-ready');
});

it('sets anonymized_at timestamp after processing', function () {
    $log = VisitLog::factory()->create([
        'processed_at' => now(),
        'created_at' => now()->subMinutes(40),
        'anonymized_at' => null,
    ]);

    $this->service->runDeferredAnonymization();

    expect($log->fresh()->anonymized_at)->not->toBeNull();
});