<?php

use Oleant\VisitAnalytics\Analyzers\Rules\Behavioral\VisitDepthRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->rule = new VisitDepthRule();
    $this->state = new AnalysisState();
    $this->params = [
        'weights' => ['single_visit' => 5],
        'depth_check_window' => 60
    ];
});

test('it identifies single page scans', function () {
    $log = VisitLog::factory()->create([
        'ip_address' => '1.1.1.1',
        'referer'    => null,
        'created_at' => now(),
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(5)
        ->and($this->state->getReasons())->toContain('single_page_scan');
});

test('it ignores visits with referer', function () {
    $log = VisitLog::factory()->create([
        'ip_address' => '1.1.1.1',
        'referer'    => 'http://google.com',
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0);
});

test('it ignores users with subsequent activity in the window', function () {
    $log1 = VisitLog::factory()->create([
        'ip_address' => '1.1.1.1',
        'referer'    => null,
        'created_at' => now(),
    ]);
    
    VisitLog::factory()->create([
        'ip_address' => '1.1.1.1',
        'created_at' => now()->addMinutes(5),
    ]);

    $this->rule->apply($log1, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0);
});