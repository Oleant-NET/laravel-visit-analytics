<?php

use Oleant\VisitAnalytics\Traits\BotnetAnalysis;

class BotnetAnalysisMock
{
    use BotnetAnalysis {
        isWhitelisted as public;
    }
}

it('skips analysis when user agent is whitelisted', function () {
    $mock = new BotnetAnalysisMock();
    
    // Define patterns: string array and a callable
    $params = [
        'whitelist_patterns' => ['Googlebot', 'Bingbot']
    ];

    expect($mock->isWhitelisted('Mozilla/5.0 (compatible; Googlebot/2.1)', $params))->toBeFalse()
        ->and($mock->isWhitelisted('Mozilla/5.0 (compatible; Bingbot/2.0)', $params))->toBeFalse();
});

it('continues analysis when user agent is not whitelisted', function () {
    $mock = new BotnetAnalysisMock();
    
    $params = [
        'whitelist_patterns' => ['Googlebot']
    ];

    expect($mock->isWhitelisted('Mozilla/5.0 (Windows NT 10.0)', $params))->toBeTrue();
});

it('handles callable whitelist patterns', function () {
    $mock = new BotnetAnalysisMock();
    
    $params = [
        'whitelist_patterns' => fn() => ['CustomBot', 'TestBot']
    ];

    expect($mock->isWhitelisted('Mozilla/5.0 (CustomBot)', $params))->toBeFalse()
        ->and($mock->isWhitelisted('Mozilla/5.0 (Normal User)', $params))->toBeTrue();
});

it('returns true if user agent is empty to avoid false positives', function () {
    $mock = new BotnetAnalysisMock();
    
    $params = ['whitelist_patterns' => ['SomeBot']];
    
    expect($mock->isWhitelisted(null, $params))->toBeTrue();
});

it('handles empty whitelist parameters gracefully', function () {
    $mock = new BotnetAnalysisMock();
    
    // Empty array or missing key
    expect($mock->isWhitelisted('SomeBot', []))->toBeTrue()
        ->and($mock->isWhitelisted('SomeBot', ['whitelist_patterns' => []]))->toBeTrue();
});