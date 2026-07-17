<?php

use Oleant\VisitAnalytics\Traits\ParsesBrowserInfo;
use Oleant\VisitAnalytics\Models\VisitLog;

// Создаем "заглушку" для тестирования
class BrowserParserMock {
    use ParsesBrowserInfo;
    public function parse($log) {
        return $this->extractBrowserInfo($log);
    }
}

it('correctly extracts chrome version from client hints', function () {
    $parser = new BrowserParserMock();
    $log = new VisitLog([
        'target_headers' => ['sec-ch-ua' => '"Google Chrome";v="120"']
    ]);

    $result = $parser->parse($log);

    expect($result)->toBe(['name' => 'chrome', 'version' => 120]);
});

it('falls back to user agent if client hints are missing', function () {
    $parser = new BrowserParserMock();
    $log = new VisitLog([
        'user_agent' => 'Mozilla/5.0 Chrome/115.0.0.0 Safari/537.36',
        'target_headers' => []
    ]);

    $result = $parser->parse($log);

    expect($result)->toBe(['name' => 'chrome', 'version' => 115]);
});

it('returns null if browser cannot be detected', function () {
    $parser = new BrowserParserMock();
    $log = new VisitLog([
        'user_agent' => 'UnknownBot/1.0',
        'target_headers' => []
    ]);

    $result = $parser->parse($log);

    expect($result)->toBeNull();
});