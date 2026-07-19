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
    Config::set('visit-analytics-collection.anonymization.anonymize_ip', false);
    $service = new IpAnonymizerService();
    expect($service->handle('192.168.1.15'))->toBe('192.168.1.15');
});

it('handles async mode correctly', function () {
    Config::set('visit-analytics-collection.anonymization.anonymize_mode', 'async');
    $service = new IpAnonymizerService();
    
    // Should NOT anonymize in default mode
    expect($service->handle('192.168.1.15', async: false))->toBe('192.168.1.15');
    // Should anonymize when final is true
    expect($service->handle('192.168.1.15', async: true))->toBe('192.168.1.0');
});
