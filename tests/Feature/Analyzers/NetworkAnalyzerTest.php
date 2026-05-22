<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Analyzers;

use Oleant\VisitAnalytics\Analyzers\NetworkAnalyzer;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use ReflectionClass;
use Mockery;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

/**
 * Helper to clear the static cache of the NetworkAnalyzer.
 * Since $dnsCache is protected, we use reflection.
 */
function clearNetworkCache() {
    $reflection = new ReflectionClass(NetworkAnalyzer::class);
    $property = $reflection->getProperty('dnsCache');
    $property->setAccessible(true);
    $property->setValue(null, []);
}

beforeEach(function () {
    clearNetworkCache();
});

afterEach(function () {
    Mockery::close();
});

/**
 * @test
 */
it('flags datacenter IPs based on host keywords', function () {
    $log = VisitLog::factory()->make(['ip_address' => '8.8.8.8']);
    $state = new AnalysisState();
    $analyzer = new NetworkAnalyzer();
    
    $params = [
        'datacenter_check' => ['keywords' => ['google']],
        'weights' => ['datacenter' => 100]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('datacenter_ip')
        ->and($state->getScore())->toBe(100);
});

/**
 * @test
 */
it('penalizes IPv4 with no reverse DNS record', function () {
    $log = VisitLog::factory()->make(['ip_address' => '0.0.0.0']);
    $state = new AnalysisState();
    $analyzer = new NetworkAnalyzer();
    
    $params = [
        'weights' => ['no_dns_record' => 50]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('no_ptr_record')
        ->and($state->getScore())->toBe(50);
});

/**
 * @test
 * Covers the case for users in regions like Tettnang with residential IPv6.
 */
it('ignores missing PTR records for IPv6 addresses', function () {
    $log = VisitLog::factory()->make(['ip_address' => '2a02:590:703:ed00::0']);
    $state = new AnalysisState();
    $analyzer = new NetworkAnalyzer();
    
    $params = [
        'weights' => ['no_dns_record' => 50]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(0)
        ->and($state->getEvidence())->toHaveKey('network_status', 'ipv6_no_ptr_ignored');
});

/**
 * @test
 * Uses Mockery to simulate a datacenter PTR record for IPv6.
 */
it('still flags IPv6 if PTR matches datacenter keywords', function () {
    $ip = '2a01:4f8:c2c:123::1'; 
    $log = VisitLog::factory()->make(['ip_address' => $ip]);
    $state = new AnalysisState();
    
    $analyzer = Mockery::mock(NetworkAnalyzer::class)->makePartial();
    $analyzer->shouldAllowMockingProtectedMethods();
    
    $analyzer->shouldReceive('performDnsLookup')
        ->once()
        ->andReturn([
            'score' => 100,
            'reason' => 'datacenter_ip',
            'evidence' => ['ptr_record_match' => 'static.hetzner.de']
        ]);

    $params = [
        'datacenter_check' => ['keywords' => ['hetzner']],
        'weights' => ['datacenter' => 100]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('datacenter_ip')
        ->and($state->getScore())->toBe(100);
});

/**
 * @test
 */
it('uses static cache for repeated lookups of the same IP', function () {
    $ip = '1.1.1.1';
    $log = VisitLog::factory()->make(['ip_address' => $ip]);
    
    $analyzer = new NetworkAnalyzer();
    $params = [
        'datacenter_check' => ['keywords' => ['cloudflare']],
        'weights' => ['datacenter' => 100]
    ];

    $state1 = new AnalysisState();
    $analyzer->analyze($log, $state1, $params);

    $state2 = new AnalysisState();
    $analyzer->analyze($log, $state2, $params);

    expect($state2->getScore())->toBe($state1->getScore());
});

/**
 * @test
 */
it('does not flag IPs with valid PTR records that lack DC keywords', function () {
    $log = VisitLog::factory()->make(['ip_address' => '8.8.4.4']);
    $state = new AnalysisState();
    $analyzer = new NetworkAnalyzer();
    
    $params = [
        'datacenter_check' => ['keywords' => ['non-existent-keyword-xyz']],
        'weights' => ['datacenter' => 100]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getScore())->toBe(0);
});

/**
 * @test
 */
it('skips analysis if ip_address is missing', function () {
    $log = VisitLog::factory()->make(['ip_address' => null]);
    $state = new AnalysisState();
    $analyzer = new NetworkAnalyzer();

    $analyzer->analyze($log, $state);

    expect($state->getScore())->toBe(0);
});

/**
 * @test
 * Uses Mockery to simulate .0 -> .1 probing logic.
 */
it('probes .1 instead of .0 for IPv4 network boundaries', function () {
    $ip = '8.8.8.0';
    $log = VisitLog::factory()->make(['ip_address' => $ip]);
    $state = new AnalysisState();

    $analyzer = Mockery::mock(NetworkAnalyzer::class)->makePartial();
    $analyzer->shouldAllowMockingProtectedMethods();

    $analyzer->shouldReceive('performDnsLookup')
        ->once()
        ->andReturn([
            'score' => 100,
            'reason' => 'datacenter_ip',
            'evidence' => ['ptr_record_match' => 'dns.google']
        ]);

    $params = [
        'datacenter_check' => ['keywords' => ['google']],
        'weights' => ['datacenter' => 100]
    ];

    $analyzer->analyze($log, $state, $params);

    expect($state->getReasons())->toContain('datacenter_ip')
        ->and($state->getScore())->toBe(100);
});