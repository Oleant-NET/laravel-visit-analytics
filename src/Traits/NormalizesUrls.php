<?php

namespace Oleant\VisitAnalytics\Traits;

trait NormalizesUrls
{
    /**
     * Removes protocol, 'www.', and trailing slashes for clean comparison.
     */
    protected function cleanUrl(string $url): string
    {
        return rtrim(str_replace(['https://', 'http://', 'www.'], '', $url), '/');
    }

    /**
     * Checks if two URLs are effectively the same regardless of protocol/www.
     */
    protected function areUrlsCircular(string $url, string $referer): bool
    {
        return $this->cleanUrl($url) === $this->cleanUrl($referer);
    }
}