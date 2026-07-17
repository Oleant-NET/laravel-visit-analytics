<?php

use Oleant\VisitAnalytics\Traits\VerifiesUserAgentSignature;

/**
 * We create an anonymous class that uses the trait so we can call the 
 * protected 'isSignatureVerified' method for testing.
 */
beforeEach(function () {
    $this->tester = new class {
        use VerifiesUserAgentSignature;

        public function callVerify(string $ua, array $headers, array $params): bool
        {
            return $this->isSignatureVerified($ua, $headers, $params);
        }
    };
});

it('returns true for consistent chrome signatures', function () {
    $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
    $headers = [
        'sec-ch-ua' => '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        'sec-ch-ua-platform' => '"Windows"'
    ];
    $params = ['os_mapping' => ['Windows' => 'Windows']];

    expect($this->tester->callVerify($ua, $headers, $params))->toBeTrue();
});

it('returns false for missing client hints on modern chromium', function () {
    // Chrome 120 is > 100, so it must have Client Hints
    $ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
    $headers = []; // Missing sec-ch-ua
    $params = [];

    expect($this->tester->callVerify($ua, $headers, $params))->toBeFalse();
});

it('returns false for version mismatch between UA and client hints', function () {
    $ua = 'Mozilla/5.0 ... Chrome/120.0.0.0 ...';
    $headers = [
        'sec-ch-ua' => '"Chromium";v="100"' // Claims v100, UA says 120
    ];
    $params = [];

    expect($this->tester->callVerify($ua, $headers, $params))->toBeFalse();
});

it('returns false for OS platform mismatch', function () {
    $ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)... Chrome/120.0.0.0';
    $headers = [
        'sec-ch-ua' => '"Chromium";v="120"',
        'sec-ch-ua-platform' => '"Windows"' // Mismatch with UA "Macintosh"
    ];
    $params = [
        'os_mapping' => ['Macintosh' => 'macOS', 'Windows' => 'Windows']
    ];

    expect($this->tester->callVerify($ua, $headers, $params))->toBeFalse();
});

it('returns true when no platform mapping is required', function () {
    $ua = 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0';
    $headers = ['sec-ch-ua' => '"Chromium";v="120"'];
    $params = ['os_mapping' => []]; // No mapping defined

    expect($this->tester->callVerify($ua, $headers, $params))->toBeTrue();
});