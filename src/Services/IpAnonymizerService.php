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
     * 2. Processing stage ('final' flag for async mode).
     * 3. Entity status (whether the visitor is a bot and 'anonymize_bots' setting).
     *
     * @param string|null $ip The raw IP address to process.
     * @param bool $isBot Whether the current log entry is identified as a bot.
     * @param bool $final Set to true when called from a final processing stage (e.g., Console Command) 
     * to bypass 'async' mode restrictions.
     * @return string|null The anonymized IP or original IP based on configuration.
     */
    public function handle(?string $ip, bool $isBot = false, bool $final = false): ?string
    {
        if (empty($ip)) {
            return null;
        }

        $config = config('visit-analytics.collection', []);
        
        // 1. Check if anonymization is globally enabled
        if (!($config['anonymize_ip'] ?? true)) {
            return $ip;
        }

        // 2. Handle 'async' mode: skip masking if not in the final stage
        $mode = $config['anonymize_mode'] ?? 'sync';
        if (!$final && $mode === 'async') {
            return $ip;
        }

        // 3. Handle Bot exceptions: skip masking if it's a bot and bot anonymization is disabled
        $anonymizeBots = $config['anonymize_bots'] ?? true;
        if ($isBot && !$anonymizeBots) {
            return $ip;
        }

        return $this->mask($ip);
    }

    /**
     * Apply masking to the IP address.
     *
     * For IPv4: Masks the last octet (e.g., 1.2.3.4 -> 1.2.3.0).
     * For IPv6: Masks the last 80 bits (Interface Identifier).
     *
     * @param string $ip
     * @return string
     */
    protected function mask(string $ip): string
    {
        // IPv6 Masking
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $binaryIp = inet_pton($ip);
            $mask = inet_pton('ffff:ffff:ffff:ffff:0000:0000:0000:0000');
            return inet_ntop($binaryIp & $mask);
        }

        // IPv4 Masking
        return preg_replace('/(\d+)\.(\d+)\.(\d+)\.(\d+)/', '$1.$2.$3.0', $ip);
    }
}