<?php

namespace Oleant\VisitAnalytics\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

/**
 * Class BotnetFingerprint
 * * Represents a unique digital signature of a detected botnet cluster.
 * * @property int $id
 * @property string $ua_hash SHA-256 hash of the User-Agent.
 * @property string $user_agent Full User-Agent string.
 * @property int $hits_count Total number of requests from this cluster.
 * @property int $unique_ips_count Number of distinct IP addresses involved.
 * @property string|null $detection_reason Reason for flagging this fingerprint.
 * @property \Illuminate\Support\Carbon|null $detected_at
 * @property \Illuminate\Support\Carbon|null $last_seen_at
 * @property bool $is_active Whether this fingerprint is currently blocked.
 */
class BotnetFingerprint extends Model
{
    use HasFactory;

    /**
     * The table associated with the model.
     *
     * @var string
     */
    protected $table = 'botnet_fingerprints';

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'ua_hash',
        'user_agent',
        'hits_count',
        'unique_ips_count',
        'detection_reason',
        'detected_at',
        'last_seen_at',
        'is_active',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'detected_at' => 'datetime',
        'last_seen_at' => 'datetime',
        'is_active' => 'boolean',
        'hits_count' => 'integer',
        'unique_ips_count' => 'integer',
    ];

    /**
     * Scope a query to only include active fingerprints.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeActive($query)
    {
        return $query->where('is_active', true);
    }
}