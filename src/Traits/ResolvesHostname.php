<?php

namespace Oleant\VisitAnalytics\Traits;

/**
 * Trait ResolvesHostname
 * 
 * Provides DNS resolution capabilities with an internal static cache 
 * to prevent redundant network lookups across the same request cycle.
 */
trait ResolvesHostname
{
    /** @var array Internal cache for resolved IP addresses */
    protected static array $dnsCache = [];

    /**
     * Performs a Reverse DNS (PTR) lookup.
     * 
     * @param string $ip The IP address to resolve.
     * @return string|null The resolved hostname or null if no PTR record exists.
     */
    protected function resolveHostname(string $ip): ?string
    {
        if (isset(self::$dnsCache[$ip])) {
            return self::$dnsCache[$ip];
        }

        $isIpv6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        
        // IPv4 Edge case: handle network range ending in .0 by probing .1
        $lookupIp = (!$isIpv6 && str_ends_with($ip, '.0')) 
            ? substr($ip, 0, strrpos($ip, '.')) . '.1' 
            : $ip;

        $host = @gethostbyaddr($lookupIp);
        
        // Cache and return: result is null if lookup failed or returned the IP itself
        return self::$dnsCache[$ip] = ($host && $host !== $lookupIp) ? $host : null;
    }
}