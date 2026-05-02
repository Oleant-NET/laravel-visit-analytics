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


/**
 * Test that the command correctly identifies an official Googlebot
 * based on its legitimate IP address range and User-Agent string,
 * then flags it with the maximum confidence score.
 */
it('correctly identifies and flags official googlebot', function () {
    VisitLog::truncate();

    $log = VisitLog::create([
        'ip_address' => '66.249.66.0', // Real Google IP
        'user_agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
        'url'        => 'http://localhost/page',
        'created_at' => now(),
    ]);

    $this->artisan('visit-analytics:analyze-bots');

    $log->refresh();
    
    expect($log->is_bot)->toBeTrue()
        ->and($log->is_official_bot)->toBeTrue()
        ->and($log->bot_score)->toBe(100);
});


/**
 * Test that the bot analysis command records specific detection reasons
 * and persists metadata evidence when a request matches multiple
 * bot patterns, such as honeypot access and suspicious User-Agents.
 */
it('stores detailed reasons and evidence for bot detection', function () {
    VisitLog::truncate();

    // Simulating an attempt to access a hidden sensitive file
    $honeypotUrl = 'http://localhost/.git/config';
    $log = VisitLog::create([
        'ip_address' => '8.8.8.8',
        'user_agent' => 'Mozilla/5.0 (compatible; EvilScanner/1.0)',
        'url'        => $honeypotUrl,
        'created_at' => now(),
    ]);

    $this->artisan('visit-analytics:analyze-bots');

    $log->refresh();

    // Check detection reasons
    expect($log->bot_reasons)->toBeArray()
        ->and($log->bot_reasons)->toContain('honeypot_trap')
        ->and($log->bot_reasons)->toContain('suspicious_ua');

    // Check evidence (metadata)
    // We verify that the specific URL that triggered the trap is stored
    expect($log->bot_evidence)->toBeArray()
        ->and($log->bot_evidence)->toHaveKey('honeypot_url', $honeypotUrl);
});


/**
 * Test that flagging an IP as a bot retroactively updates its previous clean visits.
 * 
 * @return void
 */
it('updates previous visits from the same IP once it is flagged as a bot', function () {
    // Prepare: clear logs and define a suspicious IP
    VisitLog::truncate();
    $suspiciousIp = '1.2.3.4';

    // 1. Create an old "clean" visit (simulating a human)
    VisitLog::create([
        'ip_address'   => $suspiciousIp,
        'user_agent'   => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
        'url'          => 'http://localhost/home',
        'is_bot'       => false,
        'bot_score'    => 0,
        'processed_at' => now()->subHours(2), // Already processed as "safe"
    ]);

    // 2. Create a new visit that will trigger the honeypot
    VisitLog::create([
        'ip_address'   => $suspiciousIp,
        'user_agent'   => 'Mozilla/5.0 (compatible; BotScanner/1.0)',
        'url'          => 'http://localhost/.env', // Honeypot trigger
        'is_bot'       => false,
        'processed_at' => null, // Waiting for analysis
    ]);

    // 3. Run the analysis command
    $this->artisan('visit-analytics:analyze-bots');

    // 4. Assertions
    $logs = VisitLog::where('ip_address', $suspiciousIp)->get();

    // We expect both logs to be marked as bots now
    expect($logs)->toHaveCount(2);

    foreach ($logs as $log) {
        expect($log->is_bot)->toBeTrue()
            ->and($log->bot_score)->toBeGreaterThanOrEqual(100);
        
        // Check if the old visit got the retroactive reason
        if ($log->url === 'http://localhost/home') {
            expect($log->bot_reasons)->toBeArray()
                ->and($log->bot_reasons)->toContain('retroactive_cleanup');
        }
    }
});

/**
 * Test detection of technical port leaks in Referer.
 */
it('detects a bot based on technical port in referer', function () {
    VisitLog::truncate();

    config(['visit-analytics.behavioral_analysis.weights.port_leak' => 100]);
    config(['visit-analytics.behavioral_analysis.threshold' => 70]);
    config(['visit-analytics.behavioral_analysis.port_leak' => [2082]]);

    $log = VisitLog::create([
        'ip_address' => '7.7.7.7',
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'url'        => 'https://oleant.net',
        'referer'    => 'http://oleant.net:2082/',
        'created_at' => now(),
    ]);

    $this->artisan('visit-analytics:analyze-bots');

    $log->refresh();
    expect($log->is_bot)->toBeTrue()
        ->and($log->bot_reasons)->toContain('port_leak')
        ->and($log->bot_evidence)->toHaveKey('leaked_port', 2082);
});