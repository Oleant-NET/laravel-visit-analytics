<?php

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

use Oleant\VisitAnalytics\Models\VisitLog;
use Illuminate\Support\Facades\Route;
use Oleant\VisitAnalytics\Http\Middleware\TrackVisits;

beforeEach(function () {
    // Setup a dummy route that uses our middleware
    Route::get('/test-page', function () {
        return 'OK';
    })->middleware(TrackVisits::class);
});

it('records a visit in the database', function () {
    // Act: Access the route
    $this->get('/test-page');

    // Assert: Check if the log was created
    expect(VisitLog::count())->toBe(1);
    
    $log = VisitLog::first();
    expect($log->url)->toBe('http://localhost/test-page');
    expect($log->ip_address)->toBe('127.0.0.0');
});

it('anonymizes ip addresses by default', function () {
    // Act: Mock a specific IP and call route
    $this->withServerVariables(['REMOTE_ADDR' => '192.168.1.55'])
         ->get('/test-page');

    // Assert: Check if IP was masked (192.168.1.0)
    $log = VisitLog::first();
    expect($log->ip_address)->toBe('192.168.1.0');
});

it('does not record a visit for excluded IPs', function () {
    // Set the IP in config
    config(['visit-analytics.exclude.ips' => ['1.1.1.1']]);

    // Act: Visit from excluded IP
    $this->withServerVariables(['REMOTE_ADDR' => '1.1.1.1'])
         ->get('/test-page');

    // Assert: Database should be empty
    expect(VisitLog::count())->toBe(0);
});

it('does not record a visit for bots', function () {
    // Act: Visit with Googlebot User-Agent
    $this->withHeaders(['User-Agent' => 'Googlebot/2.1'])
         ->get('/test-page');

    // Assert: Should not be tracked as track_bots is false by default
    expect(VisitLog::count())->toBe(0);
});

it('filters utm parameters based on whitelist', function () {
    // Set whitelist in config
    config(['visit-analytics.whitelist' => ['utm_source', 'utm_medium']]);

    // Act: Visit with some whitelisted and some non-whitelisted params
    $this->get('/test-page?utm_source=google&utm_medium=cpc&secret_param=123');

    // Assert: Payload should only contain whitelisted keys
    $log = VisitLog::first();
    expect($log->payload)->toBe([
        'utm_source' => 'google',
        'utm_medium' => 'cpc'
    ]);
    expect($log->payload)->not->toHaveKey('secret_param');
});

it('does not record a visit for excluded paths', function () {
    config(['visit-analytics.exclude.paths' => ['admin*']]);

    // Create Route with Mask
    Route::get('/admin/dashboard', function () { return 'Admin'; })->middleware(TrackVisits::class);

    $this->get('/admin/dashboard');

    expect(VisitLog::count())->toBe(0);
});

it('does not record a visit for IPs within an excluded subnet', function () {
    // Set a CIDR range in config
    config(['visit-analytics.exclude.ips' => ['192.168.100.0/24']]);

    // Act: Visit from an IP inside that range
    $this->withServerVariables(['REMOTE_ADDR' => '192.168.100.15'])
         ->get('/test-page');

    // Assert: Database should be empty
    expect(VisitLog::count())->toBe(0);
});

it('anonymizes IPv6 addresses to a /64 prefix', function () {
    // Mock a full IPv6 address
    $ipv6 = '2001:db8:85a3:08d3:1319:8a2e:0370:7334';
    
    $this->withServerVariables(['REMOTE_ADDR' => $ipv6])
         ->get('/test-page');

    // Assert: Check if IPv6 was masked to the first 4 segments (64 bits)
    $log = VisitLog::first();
    expect($log->ip_address)->toBe('2001:db8:85a3:08d3::0');
});

it('records visits from IPs just outside the excluded subnet', function () {
    // Set a CIDR range
    config(['visit-analytics.exclude.ips' => ['10.0.0.0/8']]);

    // Act: Visit from an IP that is NOT in 10.x.x.x
    $this->withServerVariables(['REMOTE_ADDR' => '11.0.0.1'])
         ->get('/test-page');

    // Assert: Should be recorded
    expect(VisitLog::count())->toBe(1);
});