<?php

use Oleant\VisitAnalytics\Services\IpAnonymizerService;
use Tests\TestCase;

uses(TestCase::class);

beforeEach(function () {
    $this->service = new IpAnonymizerService();
});

it('returns null when ip is empty', function () {
    expect($this->service->handle(null))->toBeNull()
        ->and($this->service->handle(''))->toBeNull();
});

it('anonymizes ipv4 addresses by masking the last octet', function ($input, $expected) {
    expect($this->service->handle($input))->toBe($expected);
})->with([
    ['192.168.1.15', '192.168.1.0'],
    ['8.8.8.8', '8.8.8.0'],
    ['127.0.0.1', '127.0.0.0'],
]);

it('anonymizes ipv6 addresses by masking to /48 network', function ($input, $expected) {
    // В твоем коде маска ffff:ffff:ffff:: соответствует /48
    expect($this->service->handle($input))->toBe($expected);
})->with([
    // Полный адрес
    ['2001:db8:85a3:0000:0000:8a2e:0370:7334', '2001:db8:85a3::'],
    // Сжатый адрес
    ['2001:db8:85a3::8a2e:370:7334', '2001:db8:85a3::'],
    // Локальный хост IPv6
    ['::1', '::'],
]);

it('returns the same value if it is not a valid ip', function ($input) {
    expect($this->service->handle($input))->toBe($input);
})->with([
    'not-an-ip',
    '192.168.1',
    'google.com',
    '2001:db8:85a3:ghij'
]);

it('correctly handles ipv4 mapped ipv6 addresses', function () {
    // IPv4-mapped IPv6 (например, ::ffff:192.168.1.1)
    $ip = '::ffff:192.168.1.1';
    // Маска /48 превратит это в ::
    expect($this->service->handle($ip))->toBe('::');
});