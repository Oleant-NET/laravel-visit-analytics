<?php

use Oleant\VisitAnalytics\Models\VisitLog;
use Illuminate\Support\Str;

it('truncates the url if it exceeds 255 characters', function () {
    $log = new VisitLog();
    $longUrl = Str::random(300);
    
    $log->url = $longUrl;

    expect($log->url)->toHaveLength(255)
        ->and($log->url)->toBe(substr($longUrl, 0, 255));
});

it('keeps short urls unchanged', function () {
    $log = new VisitLog();
    $shortUrl = '/home';
    
    $log->url = $shortUrl;

    expect($log->url)->toBe($shortUrl);
});