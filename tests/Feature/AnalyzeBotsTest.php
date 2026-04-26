<?php

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

use Oleant\VisitAnalytics\Models\VisitLog;
use Carbon\Carbon;

it('flags a visit as a bot based on suspicious user agent', function () {
    VisitLog::create([
        'ip_address' => '1.1.1.1',
        'user_agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'url'        => 'http://localhost/page',
        'created_at' => now(),
    ]);

    $this->artisan('visit-analytics:analyze-bots --max=10');

    $log = VisitLog::first();
    
    expect($log->is_bot)->toBeTrue()
        ->and($log->bot_score)->toBeGreaterThan(0);
});

it('instantly flags a visit as a bot if it hits a honeypot path', function () {
    VisitLog::create([
        'ip_address' => '2.2.2.2',
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'url'        => 'http://localhost/.env', // Honeypot
        'created_at' => now(),
    ]);

    $this->artisan('visit-analytics:analyze-bots --max=10');

    $log = VisitLog::first();
    expect($log->bot_score)->toBe(100)
        ->and($log->is_bot)->toBeTrue();
});

it('retroactively flags previous session visits when an IP is confirmed as a bot', function () {
    $ip = '4.4.4.4';

    VisitLog::create([
        'ip_address'   => $ip,
        'user_agent'   => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'url'          => 'http://localhost/home',
        'is_bot'       => false,
        'processed_at' => now()->subMinutes(1),
        'created_at'   => now()->subMinutes(1),
    ]);

    VisitLog::create([
        'ip_address' => $ip,
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'url'        => 'http://localhost/wp-admin/.env',
        'created_at' => now(),
    ]);

    $this->artisan('visit-analytics:analyze-bots --max=10');

    $botCount = VisitLog::where('ip_address', $ip)->where('is_bot', true)->count();
    expect($botCount)->toBe(2);
});

it('does not flag a normal user as a bot', function () {
    config(['visit-analytics.behavioral_analysis.weights.no_dns_record' => 10]);
    config(['visit-analytics.behavioral_analysis.threshold' => 70]);

    VisitLog::create([
        'ip_address' => '5.5.5.5',
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'url'        => 'http://localhost/home',
        'referer'    => 'https://google.com',
        'created_at' => now(),
    ]);

    $this->artisan('visit-analytics:analyze-bots --max=10');

    $log = VisitLog::first();
    
    expect($log->is_bot)->toBeFalse()
        ->and($log->bot_score)->toBeLessThan(70);
});

it('accumulates score from multiple suspicious factors', function () {
    VisitLog::create([
        'ip_address' => '6.6.6.6',
        'user_agent' => 'Python-urllib/3.10',
        'url'        => 'http://localhost/deep-page',
        'referer'    => null,
        'created_at' => now(),
    ]);

    $this->artisan('visit-analytics:analyze-bots --max=10');

    $log = VisitLog::first();
    expect($log->is_bot)->toBeTrue();
});