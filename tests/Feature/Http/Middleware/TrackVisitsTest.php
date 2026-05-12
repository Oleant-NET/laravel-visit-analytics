<?php

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

use Oleant\VisitAnalytics\Models\VisitLog;
use Illuminate\Support\Facades\Route;
use Oleant\VisitAnalytics\Http\Middleware\TrackVisits;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Log;

beforeEach(function () {
    VisitLog::truncate();

    Route::get('/test-page', function () {
        return 'OK';
    })->middleware(TrackVisits::class);

    config(['visit-analytics.collection' => [
        'anonymize_ip' => true,
        'anonymize_mode' => 'sync',
        'cookie_mode' => 'exists',
        'target_headers' => ['user-agent', 'accept-language', 'cookie'],
        'whitelist' => ['utm_source', 'utm_medium'],
        'exclude' => [
            'paths' => [],
            'ips' => [],
            'emails' => [],
            'ignore_authenticated' => false,
        ]
    ]]);
});

/**
 * Functional Tracking Tests
 */

it('records a visit in the database', function () {
    $this->get('/test-page')->assertOk();
    expect(VisitLog::count())->toBe(1);
});

/**
 * IP Anonymization & Privacy Strategy Tests
 */

it('anonymizes ip addresses immediately when mode is set to sync', function () {
    config(['visit-analytics.collection.anonymize_mode' => 'sync']);

    $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.55'])
         ->get('/test-page');

    expect(VisitLog::first()->ip_address)->toBe('192.168.1.0');
});

it('preserves full ip address for later bot analysis when mode is set to async', function () {
    config(['visit-analytics.collection.anonymize_mode' => 'async']);

    $realIp = '1.2.3.4';
    $this->withServerVariables(['REMOTE_ADDR' => $realIp])
         ->get('/test-page');

    expect(VisitLog::first()->ip_address)->toBe($realIp);
});

it('skips anonymization entirely if anonymize_ip is disabled', function () {
    config(['visit-analytics.collection.anonymize_ip' => false]);

    $realIp = '8.8.8.8';
    $this->withServerVariables(['REMOTE_ADDR' => $realIp])
         ->get('/test-page');

    expect(VisitLog::first()->ip_address)->toBe($realIp);
});

/**
 * Precision & Integrity Tests
 */

it('stores timestamps with millisecond precision', function () {
    $this->get('/test-page');
    $log = VisitLog::first();

    expect($log->created_at->format('Y-m-d H:i:s.v'))
        ->toMatch('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$/');
});

/**
 * Exclusion & Filtering Logic Tests
 */

it('excludes specific users by email address', function () {
    config(['visit-analytics.collection.exclude.emails' => ['admin@oleant.dev']]);

    $user = Mockery::mock(Authenticatable::class);
    $user->shouldReceive('getAuthIdentifier')->andReturn(1);
    $user->email = 'admin@oleant.dev';

    $this->actingAs($user)->get('/test-page');
    
    expect(VisitLog::count())->toBe(0);
});

it('excludes visits from blacklisted IP subnets using CIDR', function () {
    config(['visit-analytics.collection.exclude.ips' => ['192.168.1.0/24']]);

    $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.50'])
         ->get('/test-page');
    
    expect(VisitLog::count())->toBe(0);
});

it('prevents recording visits for excluded path patterns', function () {
    config(['visit-analytics.collection.exclude.paths' => ['admin*']]);
    
    Route::get('/admin/panel', function () { return 'OK'; })->middleware(TrackVisits::class);

    $this->get('/admin/panel');
    expect(VisitLog::count())->toBe(0);
});

it('excludes visits if the referer matches an excluded path pattern', function () {
    config(['visit-analytics.collection.exclude.paths' => ['secret-page*']]);

    $this->withHeaders(['Referer' => 'https://site.com/secret-page/dashboard'])
         ->get('/test-page');

    expect(VisitLog::count())->toBe(0);
});

/**
 * Headers & Payload Metadata Tests
 */

it('detects cookie presence in exists mode', function () {
    config(['visit-analytics.collection.cookie_mode' => 'exists']);
    
    $this->withHeaders(['Cookie' => 'test_cookie=123'])
         ->get('/test-page');

    $log = VisitLog::first();
    expect($log->target_headers)->toHaveKey('cookies_present', true);
});

it('filters query payload based on whitelist configuration', function () {
    $this->get('/test-page?utm_source=google&unwanted_param=123');

    $log = VisitLog::first();
    expect($log->payload)->toBe(['utm_source' => 'google']);
    expect($log->payload)->not->toHaveKey('unwanted_param');
});
