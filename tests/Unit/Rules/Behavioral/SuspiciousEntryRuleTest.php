<?php

use Oleant\VisitAnalytics\Rules\Behavioral\SuspiciousEntryRule;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->rule = new SuspiciousEntryRule();
    $this->state = new AnalysisState();
    $this->params = ['weights' => ['suspicious_entry' => 100]];
});

test('it adds score for first visit with internal referer', function () {
    $log = VisitLog::factory()->create([
        'ip_address' => '1.1.1.1',
        'url'        => 'http://example.com/page',
        'referer'    => 'http://example.com/landing',
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(100)
        ->and($this->state->getReasons())->toContain('suspicious_entry');
});

test('it does nothing for first visit without referer', function () {
    $log = VisitLog::factory()->create([
        'ip_address' => '1.1.1.1',
        'referer'    => null,
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0);
});

test('it does nothing if previous history exists', function () {
    // 1. Создаем "предыдущий" визит
    VisitLog::factory()->create(['ip_address' => '1.1.1.1']);

    // 2. Создаем текущий визит
    $log = VisitLog::factory()->create([
        'ip_address' => '1.1.1.1',
        'url'        => 'http://example.com/page',
        'referer'    => 'http://example.com/landing',
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0);
});

test('it does nothing if referer is external', function () {
    $log = VisitLog::factory()->create([
        'ip_address' => '1.1.1.1',
        'url'        => 'http://example.com/page',
        'referer'    => 'http://google.com',
    ]);

    $this->rule->apply($log, $this->state, $this->params);

    expect($this->state->getScore())->toBe(0);
});