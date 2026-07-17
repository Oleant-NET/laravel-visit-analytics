<?php 

use Oleant\VisitAnalytics\Analyzers\Rules\Behavioral\RefererLoopRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->rule = new RefererLoopRule();
    $this->state = new AnalysisState();
});

test('it identifies referer loop anomaly', function () {
    $ip = '1.1.1.1';
    $url = 'http://site.com/page';

    // Create 3 records with self-referencing loop
    for ($i = 0; $i < 3; $i++) {
        VisitLog::factory()->create([
            'ip_address' => $ip,
            'url' => $url,
            'referer' => $url
        ]);
    }

    // This is the 4th occurrence
    $log = VisitLog::factory()->create([
        'ip_address' => $ip,
        'url' => $url,
        'referer' => $url
    ]);

    $this->rule->apply($log, $this->state, []);

    expect($this->state->getScore())->toBe(10)
        ->and($this->state->getReasons())->toContain('referer_loop')
        ->and($this->state->getEvidence())->toHaveKey('loop_count', 4);
});

test('it ignores non-looping navigation', function () {
    $log = VisitLog::factory()->create([
        'url' => 'http://site.com/page',
        'referer' => 'http://site.com/other' // Different URL
    ]);

    $this->rule->apply($log, $this->state, []);

    expect($this->state->getScore())->toBe(0);
});

test('it ignores ajax requests', function () {
    $url = 'http://site.com/page';
    $log = VisitLog::factory()->create([
        'url' => $url,
        'referer' => $url,
        'target_headers' => ['x-requested-with' => 'XMLHttpRequest']
    ]);

    $this->rule->apply($log, $this->state, []);

    expect($this->state->getScore())->toBe(0);
});