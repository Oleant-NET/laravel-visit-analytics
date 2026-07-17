<?php

use Oleant\VisitAnalytics\Analyzers\BehaviorAnalyzer;
use Oleant\VisitAnalytics\Models\VisitLog;
use Oleant\VisitAnalytics\Support\AnalysisState;
use Oleant\VisitAnalytics\Contracts\RuleInterface;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->analyzer = new BehaviorAnalyzer();
    $this->log = new VisitLog();
    $this->state = Mockery::mock(AnalysisState::class);
});

it('does nothing if the ip address is missing', function () {
    $this->log->ip_address = null;

    $this->state->shouldNotReceive('getScore');

    $this->analyzer->analyze($this->log, $this->state, []);
});

it('iterates through the rules and applies them', function () {
    $this->log->ip_address = '127.0.0.1';
    
    $this->state->shouldReceive('getScore')->andReturn(0);
    
    $ruleMock = Mockery::mock(RuleInterface::class);
    $ruleMock->shouldReceive('apply')
        ->once()
        ->with($this->log, $this->state, Mockery::any())
        ->andReturn();

    $this->app->instance('MyRule', $ruleMock);

    $this->analyzer->analyze($this->log, $this->state, [
        'rules' => ['MyRule']
    ]);
});

it('breaks the loop if the score threshold is reached', function () {
    $this->log->ip_address = '127.0.0.1';
    
    $this->state->shouldReceive('getScore')->andReturn(75);
    
    $ruleMock = Mockery::mock(RuleInterface::class);
    $ruleMock->shouldNotReceive('apply');

    $this->app->instance('MyRule', $ruleMock);

    $this->analyzer->analyze($this->log, $this->state, [
        'rules' => ['MyRule']
    ]);
});

it('uses a custom threshold if provided in parameters', function () {
    $this->log->ip_address = '127.0.0.1';
    
    $this->state->shouldReceive('getScore')->andReturn(60);
    
    $ruleMock = Mockery::mock(RuleInterface::class);
    $ruleMock->shouldNotReceive('apply');

    $this->app->instance('MyRule', $ruleMock);

    $this->analyzer->analyze($this->log, $this->state, [
        'rules' => ['MyRule'],
        'threshold' => 50
    ]);
});