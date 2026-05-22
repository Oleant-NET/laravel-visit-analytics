<?php

namespace Oleant\VisitAnalytics\Services;

use Oleant\VisitAnalytics\Models\VisitLog;

/**
 * Class IpAnonymizerService
 *
 * Provides functionality to mask IP addresses based on compliance requirements (GDPR/DSGVO).
 * Supports both IPv4 and IPv6, and respects asynchronous processing modes.
 */
class IpAnonymizerService
{
    /**
     * Configuration
     *
     * @var array
     */
    protected array $config = [];

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->config = config('visit-analytics.collection.anonymization', []);
    }

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

        // 1. Check if anonymization is globally enabled
        if (!($this->config['anonymize_ip'] ?? true)) {
            return $ip;
        }

        // 2. Handle 'async' mode: skip masking if not in the final stage
        $mode = $this->config['anonymize_mode'] ?? 'sync';
        if (!$final && $mode === 'async') {
            return $ip;
        }

        // 3. Handle Bot exceptions: skip masking if it's a bot and bot anonymization is disabled
        $anonymizeBots = $this->config['anonymize_bots'] ?? true;
        if ($isBot && !$anonymizeBots) {
            return $ip;
        }

        return $this->mask($ip);
    }

    /**
     * Performs deferred anonymization of processed visit logs.
     * * This method masks IP addresses for logs that have already been processed 
     * and have exceeded the retention period defined in the configuration. 
     * It ensures that sensitive data is kept only as long as necessary for 
     * retroactive analysis and cluster detection.
     *
     * @return int
     */
    public function runDeferredAnonymization(): int
    {
        $retentionMinutes = (int) ($this->config['anonymize_retention_minutes'] ?? 30);
        $anonymizeBots = (bool) ($this->config['anonymize_bots'] ?? true);
        $thresholdTime = now()->subMinutes($retentionMinutes);

        // Fetch logs that are processed, pending anonymization, and past the retention window
        $query = VisitLog::whereNotNull('processed_at')
            ->whereNull('anonymized_at')
            ->where('created_at', '<', $thresholdTime);

        // Exclude bots if bot anonymization is disabled to preserve raw data
        if (!$anonymizeBots) {
            $query->where('is_bot', false);
        }

        $count = 0;

        $query->chunkById(500, function ($logs) use (&$count) {
            foreach ($logs as $log) {
                $log->update([
                    'ip_address'    => $this->handle($log->ip_address, (bool)$log->is_bot, final: true),
                    'anonymized_at' => now(),
                ]);
                $count++;
            }
        });

        return $count;
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
            $binaryIp = inet_pton($ip);
            $mask = inet_pton('ffff:ffff:ffff:ffff:0000:0000:0000:0000');
            return inet_ntop($binaryIp & $mask);
        }

        // IPv4 Masking: Ensure it's a valid IPv4 before applying regex
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return preg_replace('/(\d+)\.(\d+)\.(\d+)\.(\d+)/', '$1.$2.$3.0', $ip);
        }

        return $ip; // Fallback if IP is invalid
    }
}