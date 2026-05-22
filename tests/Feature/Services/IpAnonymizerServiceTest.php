<?php

use Oleant\VisitAnalytics\Services\IpAnonymizerService;
use Tests\TestCase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Carbon;
use Oleant\VisitAnalytics\Models\VisitLog;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->service = new IpAnonymizerService();
});

// --- Original Logic Tests ---

it('returns null when ip is empty', function () {
    expect($this->service->handle(null))->toBeNull()
        ->and($this->service->handle(''))->toBeNull();
});

it('anonymizes ipv4 correctly', function ($input, $expected) {
    expect($this->service->handle($input))->toBe($expected);
})->with([
    ['192.168.1.15', '192.168.1.0'],
    ['8.8.8.8', '8.8.8.0'],
    ['127.0.0.1', '127.0.0.0'],
]);

it('anonymizes ipv6 correctly to /64', function ($input, $expected) {
    expect($this->service->handle($input))->toBe($expected);
})->with([
    ['2001:db8:85a3:0000:0000:8a2e:0370:7334', '2001:db8:85a3::'],
    ['2001:db8:85a3::8a2e:370:7334', '2001:db8:85a3::'],
    ['::1', '::'],
]);

it('returns original value for invalid IPs', function ($input) {
    expect($this->service->handle($input))->toBe($input);
})->with([
    'not-an-ip',
    '192.168.1',
    'google.com',
    '2001:db8:85a3:ghij'
]);

it('handles ipv4 mapped ipv6 correctly', function () {
    expect($this->service->handle('::ffff:192.168.1.1'))->toBe('::');
});

// --- Config & Security Tests ---

it('returns original IP when global anonymization is disabled', function () {
    Config::set('visit-analytics.collection.anonymization.anonymize_ip', false);
    $service = new IpAnonymizerService();
    expect($service->handle('192.168.1.15'))->toBe('192.168.1.15');
});

it('skips anonymization for bots if anonymize_bots is false', function () {
    Config::set('visit-analytics.collection.anonymization.anonymize_bots', false);
    $service = new IpAnonymizerService();
    expect($service->handle('192.168.1.15', isBot: true))->toBe('192.168.1.15');
});

it('handles async mode correctly', function () {
    Config::set('visit-analytics.collection.anonymization.anonymize_mode', 'async');
    $service = new IpAnonymizerService();
    
    // Should NOT anonymize in default mode
    expect($service->handle('192.168.1.15', final: false))->toBe('192.168.1.15');
    // Should anonymize when final is true
    expect($service->handle('192.168.1.15', final: true))->toBe('192.168.1.0');
});

// --- Deferred Anonymization Tests ---

it('executes deferred anonymization only for old logs', function () {
    Config::set('visit-analytics.collection.anonymization.anonymize_retention_minutes', 30);
    $service = new IpAnonymizerService();
    
    Carbon::setTestNow(now());

    $oldLog = VisitLog::factory()->create([
        'ip_address' => '1.1.1.1',
        'processed_at' => now(),
        'anonymized_at' => null,
        'created_at' => now()->subMinutes(31),
    ]);

    $recentLog = VisitLog::factory()->create([
        'ip_address' => '2.2.2.2',
        'processed_at' => now(),
        'anonymized_at' => null,
        'created_at' => now()->subMinutes(29),
    ]);

    $count = $service->runDeferredAnonymization();

    expect($count)->toBe(1)
        ->and($oldLog->fresh()->ip_address)->toBe('1.1.1.0')
        ->and($recentLog->fresh()->ip_address)->toBe('2.2.2.2');
});

/**
 * @test
 */
it('skips bot anonymization when the config is disabled', function () {
    // 1. Disable bot anonymization
    config(['visit-analytics.collection.anonymization.anonymize_bots' => false]);

    $originalIp = '1.2.3.4';
    
    // 2. Create a bot log that should NOT be anonymized
    $log = VisitLog::factory()->create([
        'ip_address' => $originalIp,
        'is_bot' => true,
        'processed_at' => now(),
        'anonymized_at' => null,
        'created_at' => now()->subMinutes(60), // Outside retention window
    ]);

    $service = new IpAnonymizerService();
    $count = $service->runDeferredAnonymization();

    $log->refresh();

    // 3. Assertions
    expect($count)->toBe(0) // Nothing was processed
        ->and($log->ip_address)->toBe($originalIp) // IP remains intact
        ->and($log->anonymized_at)->toBeNull(); // Still marked as non-anonymized
});