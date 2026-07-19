<?php

use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Rules\Referer\SelfRefererRule;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);
uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->rule = new SelfRefererRule();
    $this->state = new AnalysisState();
});

it('does not penalize legitimate same-origin requests', function () {
    $log = VisitLog::factory()->create([
        'url' => 'https://site.com/page',
        'referer' => 'https://site.com/home',
        'target_headers' => ['sec-fetch-site' => 'same-origin']
    ]);

    $this->rule->apply($log, $this->state, []);

    expect($this->state->getScore())->toBe(0);
});

it('penalizes 100 points for impossible self-referer on the first visit', function () {
    $log = VisitLog::factory()->create([
        'url' => 'https://site.com/page',
        'referer' => 'https://site.com/page', // Self-reference
        'target_headers' => ['sec-fetch-site' => 'cross-site'] // Missing same-origin header
    ]);

    $this->rule->apply($log, $this->state, []);

    expect($this->state->getScore())->toBe(100)
        ->and($this->state->getReasons())->toContain('impossible_self_referer')
        ->and($this->state->getEvidenceValue('impossible_self_referer'))
            ->toBe(['anomaly' => 'self_ref_on_first_visit']);
});

it('penalizes loop on subsequent visits', function () {
    $ip = '1.1.1.1';
    $url = 'https://site.com/page';

    // 1. First visit (to make current log "subsequent")
    VisitLog::factory()->create(['ip_address' => $ip, 'url' => $url, 'id' => 1]);

    // 2. Current loop log
    $log = VisitLog::factory()->create([
        'ip_address' => $ip,
        'url' => $url,
        'referer' => $url,
        'target_headers' => ['sec-fetch-site' => 'cross-site'],
        'id' => 2
    ]);

    $this->rule->apply($log, $this->state, ['score' => 60]);

    expect($this->state->getScore())->toBe(60)
        ->and($this->state->getReasons())->toContain('referer_loop');
});