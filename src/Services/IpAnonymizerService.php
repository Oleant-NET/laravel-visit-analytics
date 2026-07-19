<?php

namespace Oleant\VisitAnalytics\Services;

/**
 * Class IpAnonymizerService
 *
 * Provides functionality to mask IP addresses based on compliance requirements (GDPR/DSGVO).
 * Supports both IPv4 and IPv6, and respects asynchronous processing modes.
 */
class IpAnonymizerService
{
    /**
     * Handle IP anonymization logic.
     *
     * This method decides whether to mask the IP address based on:
     * 1. Global 'anonymize_ip' setting.
     * 
     * @param string|null $ip The raw IP address to process.
     * @return string|null The anonymized IP or original IP based on configuration.
     */
    public function handle(?string $ip, bool $async = false): ?string
    {
        if (empty($ip)) {
            return null;
        }

        $config = config('visit-analytics-collection.anonymization', []);

        // Check if anonymization is globally enabled
        if (!($config['anonymize_ip'] ?? true)) {
            return $ip;
        }

        if ($config['anonymize_mode'] === 'async' && !$async) {
            return $ip;
        }

        return $this->mask($ip);
    }

    /**
     * Apply masking to the IP address.
     *
     * For IPv4: Masks the last octet (e.g., 1.2.3.4 -> 1.2.3.0).
     * For IPv6: Masks the last 64 bits (Interface Identifier).
     *
     * @param string $ip
     * @return string
     */
    protected function mask(string $ip): string
    {
        // IPv6 Masking: Applying /64 prefix (masking last 64 bits)
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $packed = inet_pton($ip);
            $mask = str_repeat("\xff", 8) . str_repeat("\x00", 8);
            return inet_ntop($packed & $mask);
        }

        // IPv4 Masking
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return long2ip(ip2long($ip) & ~255);
        }

        return $ip;
    }
}