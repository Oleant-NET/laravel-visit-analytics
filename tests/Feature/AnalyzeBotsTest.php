<?php

uses(\Oleant\VisitAnalytics\Tests\TestCase::class);

use Oleant\VisitAnalytics\Models\VisitLog;
use Carbon\Carbon;

/**
 * Test to verify that suspicious User-Agents are flagged correctly.
 */
it('flags a visit as a bot based on suspicious user agent', function () {
    VisitLog::truncate();

    config(['visit-analytics.behavioral_analysis.weights.ua' => 100]);
    config(['visit-analytics.behavioral_analysis.threshold' => 70]);

    $log = VisitLog::create([
        'ip_address' => '1.1.1.1',
        'user_agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'url'        => 'http://localhost/page',
        'created_at' => now(),
    ]);

    $this->artisan('visit-analytics:analyze-bots --max=10');

    $log->refresh();
    expect($log->is_bot)->toBeTrue();
});

/**
 * Test for instant bot detection when a honeypot path is accessed.
 */
it('instantly flags a visit as a bot if it hits a honeypot path', function () {
    VisitLog::truncate();

    VisitLog::create([
        'ip_address' => '2.2.2.2',
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'url'        => 'http://localhost/.env',
        'created_at' => now(),
    ]);

    $this->artisan('visit-analytics:analyze-bots --max=10');

    $log = VisitLog::first();
    expect($log->bot_score)->toBe(100)
        ->and($log->is_bot)->toBeTrue();
});

/**
 * Test detection of "referer loops" (Referer == URL) on the first visit.
 */
it('detects a bot faking a referer loop on the first visit', function () {
    VisitLog::truncate();
    
    // Set referer_loop to 100 to ensure instant bot flag
    config(['visit-analytics.behavioral_analysis.weights.referer_loop' => 100]);
    config(['visit-analytics.behavioral_analysis.threshold' => 70]);

    $url = 'https://oleant.dev/leistungen';
    $log = VisitLog::create([
        'ip_address' => '45.84.107.0',
        'url'        => $url,
        'referer'    => $url,
        'user_agent' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X)',
        'created_at' => now(),
    ]);

    $this->artisan('visit-analytics:analyze-bots --max=10');

    $log->refresh();
    
    expect($log->is_bot)->toBeTrue()
        ->and($log->bot_score)->toBeGreaterThanOrEqual(100);
});

/**
 * Test normalization of Referer strings.
 */
it('detects a bot faking a referer with normalization', function () {
    VisitLog::truncate();

    config(['visit-analytics.behavioral_analysis.weights.referer_loop' => 100]);
    config(['visit-analytics.behavioral_analysis.threshold' => 70]);

    $log = VisitLog::create([
        'ip_address' => '185.170.114.0',
        'url'        => 'https://oleant.dev',
        'referer'    => 'oleant.dev', 
        'user_agent' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 12_0 like Mac OS X)',
        'created_at' => now(),
    ]);

    $this->artisan('visit-analytics:analyze-bots --max=10');

    $log->refresh();
    expect($log->is_bot)->toBeTrue();
});

/**
 * Test retroactive flagging of all IP sessions.
 */
it('retroactively flags previous session visits when an IP is confirmed as a bot', function () {
    VisitLog::truncate();
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

/**
 * Test that normal human traffic remains unflagged.
 */
it('does not flag a normal user as a bot', function () {
    VisitLog::truncate();
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
    expect($log->is_bot)->toBeFalse();
});

/**
 * Test score accumulation.
 */
it('accumulates score from multiple suspicious factors', function () {
    VisitLog::truncate();

    config(['visit-analytics.behavioral_analysis.weights.ua' => 40]);
    config(['visit-analytics.behavioral_analysis.weights.no_referer' => 40]);
    config(['visit-analytics.behavioral_analysis.threshold' => 70]);

    $log = VisitLog::create([
        'ip_address' => '6.6.6.6',
        'user_agent' => 'Custom-Bot-Script/1.0', 
        'url'        => 'http://localhost/deep-page',
        'referer'    => null,
        'created_at' => now(),
    ]);

    $this->artisan('visit-analytics:analyze-bots --max=10');

    $log->refresh();
    expect($log->is_bot)->toBeTrue();
});