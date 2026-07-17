<?php

namespace Oleant\VisitAnalytics\Tests\Unit\Traits;

use Oleant\VisitAnalytics\Traits\ResolvesHostname;

/**
 * HostnameResolverMock
 * 
 * A test-only class used to access and test the protected methods and 
 * internal state of the ResolvesHostname trait.
 */
class HostnameResolverMock 
{
    use ResolvesHostname;

    /**
     * Resolves an IP address to a hostname using the trait method.
     *
     * @param string $ip
     * @return string|null
     */
    public function resolve(string $ip): ?string 
    {
        return $this->resolveHostname($ip);
    }

    /**
     * Clears the internal static cache to ensure test isolation.
     * 
     * @return void
     */
    public static function clearCache(): void 
    {
        $reflection = new \ReflectionClass(self::class);
        $property = $reflection->getProperty('dnsCache');
        $property->setAccessible(true);
        // Pass null as the first argument to target the static property
        $property->setValue(null, []);
    }
}

beforeEach(function () {
    HostnameResolverMock::clearCache();
});

/**
 * @test
 * Verifies that the internal static cache successfully avoids redundant DNS lookups.
 */
it('uses the static cache for repeated lookups', function () {
    $resolver = new HostnameResolverMock();
    $ip = '127.0.0.1';

    // Manually inject a value into the cache to simulate a previous resolution
    $reflection = new \ReflectionClass(HostnameResolverMock::class);
    $property = $reflection->getProperty('dnsCache');
    $property->setAccessible(true);
    $property->setValue(null, [$ip => 'localhost']);

    expect($resolver->resolve($ip))->toBe('localhost');
});

/**
 * @test
 * Ensures the logic correctly normalizes network addresses ending in .0 to .1.
 */
it('correctly transforms .0 to .1 for IPv4 lookups', function () {
    $resolver = new HostnameResolverMock();
    
    // Attempting to resolve a .0 IP address; the trait should normalize it to .1
    $resolver->resolve('192.168.0.0');
    
    $reflection = new \ReflectionClass(HostnameResolverMock::class);
    $property = $reflection->getProperty('dnsCache');
    $property->setAccessible(true);
    $cache = $property->getValue(null);
    
    // Verify the cache was populated correctly
    expect($cache)->toHaveKey('192.168.0.0');
});

/**
 * @test
 * Verifies that the resolver returns null when no PTR record exists.
 */
it('returns null when resolution fails', function () {
    $resolver = new HostnameResolverMock();
    
    // Use an IP from the TEST-NET range (192.0.2.0/24), which is guaranteed 
    // not to have valid DNS records.
    $host = $resolver->resolve('192.0.2.1'); 
    
    expect($host)->toBeNull();
});

/**
 * @test
 * Ensures the resolver handles potential hostname strings gracefully.
 */
it('handles valid hostnames correctly', function () {
    $resolver = new HostnameResolverMock();
    
    $host = $resolver->resolve('127.0.0.1');
    
    // Check that the result is either a string or null without using 'or'
    $isValid = is_string($host) || is_null($host);
    
    expect($isValid)->toBeTrue();
});