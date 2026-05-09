<?php

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

use Oleant\VisitAnalytics\Models\VisitLog;
use Illuminate\Support\Facades\Route;
use Oleant\VisitAnalytics\Http\Middleware\TrackVisits;
use Illuminate\Contracts\Auth\Authenticatable;

beforeEach(function () {
    VisitLog::truncate();

    Route::get('/test-page', function () {
        return 'OK';
    })->middleware(TrackVisits::class);

    config(['visit-analytics.collection' => [
        'anonymize_ip' => true,
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
 * Functional Tests
 */

it('records a visit in the database', function () {
    $this->get('/test-page')->assertOk();
    expect(VisitLog::count())->toBe(1);
});

it('anonymizes ip addresses', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.55'])
         ->get('/test-page');

    expect(VisitLog::first()->ip_address)->toBe('192.168.1.0');
});

/**
 * Exclusion Logic
 */

it('excludes specific users by email', function () {
    config(['visit-analytics.collection.exclude.emails' => ['admin@oleant.dev']]);

    // Create a mock user that implements Authenticatable
    $user = Mockery::mock(Authenticatable::class);
    $user->shouldReceive('getAuthIdentifier')->andReturn(1);
    $user->email = 'admin@oleant.dev';

    $this->actingAs($user)->get('/test-page');
    
    expect(VisitLog::count())->toBe(0);
});

it('excludes all authenticated users when ignore_authenticated is true', function () {
    config(['visit-analytics.collection.exclude.ignore_authenticated' => true]);

    $user = Mockery::mock(Authenticatable::class);
    $user->shouldReceive('getAuthIdentifier')->andReturn(1);
    $user->email = 'any@user.com';

    $this->actingAs($user)->get('/test-page');
    
    expect(VisitLog::count())->toBe(0);
});

it('does not record a visit for excluded paths', function () {
    config(['visit-analytics.collection.exclude.paths' => ['admin*']]);
    
    Route::get('/admin/panel', function () { return 'OK'; })->middleware(TrackVisits::class);

    $this->get('/admin/panel');
    expect(VisitLog::count())->toBe(0);
});

/**
 * Headers & Cookies
 */

it('handles cookies in "exists" mode', function () {
    config(['visit-analytics.collection.cookie_mode' => 'exists']);
    
    // Use withHeaders to ensure the 'cookie' header is physically present
    $this->withHeaders(['Cookie' => 'test_cookie=123'])
         ->get('/test-page');

    $log = VisitLog::first();
    expect($log->target_headers)->toHaveKey('cookies_present', true);
});

it('handles cookies in "full" mode', function () {
    config(['visit-analytics.collection.cookie_mode' => 'full']);
    
    $this->withHeaders(['Cookie' => 'session=xyz'])
         ->get('/test-page');

    $log = VisitLog::first();
    expect($log->target_headers['cookie'])->toBe('session=xyz');
});

it('filters payload based on whitelist', function () {
    $this->get('/test-page?utm_source=google&bad_param=123');

    $log = VisitLog::first();
    expect($log->payload)->toBe(['utm_source' => 'google']);
    expect($log->payload)->not->toHaveKey('bad_param');
});

/**
 * Reliability
 */

it('does not crash the application if config is broken', function () {
    // Pass empty array instead of null to satisfy type hint array
    config(['visit-analytics.collection' => []]);

    $this->get('/test-page')->assertStatus(200);
});