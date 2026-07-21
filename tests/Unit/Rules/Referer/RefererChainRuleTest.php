<?php

use Oleant\VisitAnalytics\Rules\Referer\RefererChainRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->rule = new RefererChainRule();
    $this->state = new AnalysisState();
    $this->params = [
        'cumulative' => ['no_referer_increment' => 5]
    ];
});

test('it identifies direct navigation via sec-fetch-site header', function () {
    $log = VisitLog::factory()->create([
        'referer' => null,
        'target_headers' => ['sec-fetch-site' => 'none']
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    // Проверяем, что в массиве evidence есть нужный ключ
    expect($this->state->getEvidence())->toHaveKey('referer_source', 'direct_navigation')
        ->and($this->state->getScore())->toBe(0);
});

test('it identifies page refresh', function () {
    $prev = VisitLog::factory()->create(['url' => 'http://site.com/page']);
    $log = VisitLog::factory()->create([
        'ip_address' => $prev->ip_address,
        'url' => 'http://site.com/page',
        'referer' => null
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    // Проверяем, что в массиве evidence есть нужный ключ
    expect($this->state->getEvidence())->toHaveKey('nav_type', 'page_refresh')
        ->and($this->state->getScore())->toBe(0);
});

test('it flags broken referer chain when navigation is suspicious', function () {
    $prev = VisitLog::factory()->create(['url' => 'http://site.com/page-a']);
    $log = VisitLog::factory()->create([
        'ip_address' => $prev->ip_address,
        'url' => 'http://site.com/page-b', // Different URL
        'referer' => null,
        'target_headers' => ['sec-fetch-site' => 'cross-site'] // Not 'none'
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(5)
        ->and($this->state->getReasons())->toContain('broken_referer_chain');
});