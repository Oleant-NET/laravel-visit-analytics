<?php

use Oleant\VisitAnalytics\Traits\NormalizesUrls;

class NormalizerMock { 
    use NormalizesUrls {
        cleanUrl as public;
        areUrlsCircular as public;
    }
}

it('normalizes URLs by stripping protocol and www', function () {
    $mock = new NormalizerMock();
    
    expect($mock->cleanUrl('https://www.google.com/test/'))
        ->toBe('google.com/test');
        
    expect($mock->cleanUrl('http://site.com'))
        ->toBe('site.com');
});

it('detects circular loop between two urls', function () {
    $mock = new NormalizerMock();
    
    expect($mock->areUrlsCircular('https://site.com/a', 'http://www.site.com/a/'))
        ->toBeTrue();
        
    expect($mock->areUrlsCircular('site.com/a', 'site.com/b'))
        ->toBeFalse();
});