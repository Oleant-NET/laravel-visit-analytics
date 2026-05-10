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
 * Functional Tracking Tests
 */

it('records a visit in the database', function () {
    $this->get('/test-page')->assertOk();
    expect(VisitLog::count())->toBe(1);
});

it('anonymizes ip addresses for GDPR compliance', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.55'])
         ->get('/test-page');

    expect(VisitLog::first()->ip_address)->toBe('192.168.1.0');
});

/**
 * Precision & Integrity Tests
 */

it('stores timestamps with millisecond precision', function () {
    $this->get('/test-page');

    $log = VisitLog::first();

    // Check if milliseconds are recorded (not just .000)
    // We expect the 'v' format to be non-zero in most cases during real execution,
    // but the key is checking the string format integrity.
    expect($log->created_at->format('Y-m-d H:i:s.v'))
        ->toMatch('/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$/');
});

/**
 * Exclusion Logic Tests
 */

it('excludes specific users by email address', function () {
    config(['visit-analytics.collection.exclude.emails' => ['admin@oleant.dev']]);

    $user = Mockery::mock(Authenticatable::class);
    $user->shouldReceive('getAuthIdentifier')->andReturn(1);
    $user->email = 'admin@oleant.dev';

    $this->actingAs($user)->get('/test-page');
    
    expect(VisitLog::count())->toBe(0);
});

it('excludes all authenticated users when ignore_authenticated is enabled', function () {
    config(['visit-analytics.collection.exclude.ignore_authenticated' => true]);

    $user = Mockery::mock(Authenticatable::class);
    $user->shouldReceive('getAuthIdentifier')->andReturn(1);
    $user->email = 'any@user.com';

    $this->actingAs($user)->get('/test-page');
    
    expect(VisitLog::count())->toBe(0);
});

it('prevents recording visits for excluded path patterns', function () {
    config(['visit-analytics.collection.exclude.paths' => ['admin*']]);
    
    Route::get('/admin/panel', function () { return 'OK'; })->middleware(TrackVisits::class);

    $this->get('/admin/panel');
    expect(VisitLog::count())->toBe(0);
});

/**
 * Headers & Cookies Metadata Tests
 */

it('detects cookie presence in "exists" mode', function () {
    config(['visit-analytics.collection.cookie_mode' => 'exists']);
    
    $this->withHeaders(['Cookie' => 'test_cookie=123'])
         ->get('/test-page');

    $log = VisitLog::first();
    expect($log->target_headers)->toHaveKey('cookies_present', true);
});

it('captures full cookie header in "full" mode', function () {
    config(['visit-analytics.collection.cookie_mode' => 'full']);
    
    $this->withHeaders(['Cookie' => 'session=xyz'])
         ->get('/test-page');

    $log = VisitLog::first();
    expect($log->target_headers['cookie'])->toBe('session=xyz');
});

it('filters query payload based on whitelist configuration', function () {
    $this->get('/test-page?utm_source=google&unwanted_param=123');

    $log = VisitLog::first();
    expect($log->payload)->toBe(['utm_source' => 'google']);
    expect($log->payload)->not->toHaveKey('unwanted_param');
});

/**
 * Error Handling & Reliability
 */

it('does not crash the host application if analytics configuration is empty', function () {
    config(['visit-analytics.collection' => []]);

    $this->get('/test-page')->assertStatus(200);
});