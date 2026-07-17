<?php

use Oleant\VisitAnalytics\Traits\QueriesVisitHistory;
use Oleant\VisitAnalytics\Models\VisitLog;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Faker\Factory as FakerFactory;
use Faker\Provider\Internet;
use Faker\Provider\UserAgent;

/**
 * Mock class to expose protected trait methods for testing purposes.
 */
class HistoryMock { 
    use QueriesVisitHistory {
        isInitialDirectHit as public;
        getSequentialDirectHitsCount as public;
        hasVisitedUrlBefore as public;
    }
}

uses(RefreshDatabase::class);
uses(\Oleant\VisitAnalytics\Tests\TestCase::class, RefreshDatabase::class);

beforeEach(function () {
    $this->mock = new HistoryMock();

    // Forcefully register the missing providers for the factory's generator
    $faker = \Faker\Factory::create();
    $faker->addProvider(new Internet($faker));
    $faker->addProvider(new UserAgent($faker));
    
    // Bind the corrected faker to the container if necessary
    app()->singleton(\Faker\Generator::class, function () use ($faker) {
        return $faker;
    });
});

it('detects if the first log in window is a direct hit', function () {
    $ip = '127.0.0.1';
    
    // Create an initial visit with 'none' fetch-site indicating a direct entry
    $first = VisitLog::factory()->create([
        'ip_address' => $ip,
        'target_headers' => ['sec-fetch-site' => 'none'],
        'created_at' => now()->subMinutes(2)
    ]);

    // Create the current visit log being analyzed
    $current = VisitLog::factory()->create(['ip_address' => $ip, 'id' => $first->id + 1]);

    expect($this->mock->isInitialDirectHit($current, 5))->toBeTrue();
});

it('counts sequential direct hits (empty referers) correctly', function () {
    $ip = '127.0.0.1';
    
    // Create 3 logs with no referer within the last 5 minutes
    VisitLog::factory()->count(3)->create([
        'ip_address' => $ip,
        'referer' => null,
        'created_at' => now()->subMinute()
    ]);

    $current = VisitLog::factory()->create(['ip_address' => $ip]);

    // Should detect the 3 previous direct hits
    expect($this->mock->getSequentialDirectHitsCount($current, 5))->toBe(3);
});

it('verifies if URL was visited before in the session', function () {
    $ip = '127.0.0.1';
    $url = 'https://site.com/target';

    // Insert a past record for this IP and URL
    VisitLog::factory()->create([
        'ip_address' => $ip,
        'url' => $url,
        'id' => 10
    ]);

    $current = VisitLog::factory()->create(['id' => 20]);

    // Check if history correctly identifies the existing visit
    expect($this->mock->hasVisitedUrlBefore($ip, $url, 20))->toBeTrue()
        ->and($this->mock->hasVisitedUrlBefore($ip, 'https://site.com/other', 20))->toBeFalse();
});