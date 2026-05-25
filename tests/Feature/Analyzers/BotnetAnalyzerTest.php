<?php

namespace Oleant\VisitAnalytics\Tests\Feature\Analyzers;

use Oleant\VisitAnalytics\Analyzers\BotnetAnalyzer;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

it('updates database correctly when a cluster is detected', function () {
    $hash = 'cluster_hash_123';
    
    $log1 = VisitLog::factory()->create([
        'fingerprint_hash' => $hash,
        'ip_address' => '1.1.1.1'
    ]);
    
    VisitLog::factory()->create([
        'fingerprint_hash' => $hash,
        'ip_address' => '2.2.2.2'
    ]);

    $state = new AnalysisState();
    $analyzer = new BotnetAnalyzer();

    $analyzer->analyze($log1, $state, [
        'weights' => ['cluster_anomaly_weight' => 50]
    ]);

    $log1->refresh();
    
    expect($log1->is_bot)->toBeTrue()
        ->and((int) $log1->bot_score)->toBe(50)
        ->and($log1->bot_reasons)->toBeArray()->toContain('botnet_cluster_match');
});

it('does not mark as bot if cluster not found', function () {
    $log = VisitLog::factory()->create([
        'fingerprint_hash' => 'unique_hash',
        'ip_address' => '1.1.1.1'
    ]);

    $state = new AnalysisState();
    $analyzer = new BotnetAnalyzer();

    $analyzer->analyze($log, $state);

    $log->refresh();
    
    expect($log->is_bot)->toBeFalse();
});

it('does not mark as bot if state is already official bot', function () {
    $log = VisitLog::factory()->create(['fingerprint_hash' => 'hash']);
    $state = new AnalysisState();
    $state->isOfficialBot = true;

    $analyzer = new BotnetAnalyzer();
    $analyzer->analyze($log, $state);

    $log->refresh();
    expect($log->is_bot)->toBeFalse();
});

it('skips analysis if fingerprint hash is empty', function () {
    $log = VisitLog::factory()->create(['fingerprint_hash' => null]);
    $state = new AnalysisState();

    $analyzer = new BotnetAnalyzer();
    $analyzer->analyze($log, $state);

    $log->refresh();
    expect($log->is_bot)->toBeFalse();
});

it('does not mark as bot if only one IP exists for the fingerprint', function () {
    $hash = 'same_ip_hash';
    $log1 = VisitLog::factory()->create(['fingerprint_hash' => $hash, 'ip_address' => '1.1.1.1']);
    VisitLog::factory()->create(['fingerprint_hash' => $hash, 'ip_address' => '1.1.1.1']);

    $state = new AnalysisState();
    $analyzer = new BotnetAnalyzer();

    $analyzer->analyze($log1, $state);

    $log1->refresh();
    expect($log1->is_bot)->toBeFalse();
});