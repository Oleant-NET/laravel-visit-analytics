<?php

namespace Oleant\VisitAnalytics\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * @property string $ip_address
 * @property string $user_agent
 * @property string $url
 * @property string $referer
 * @property array $payload
 */
class VisitLog extends Model
{
    // We only need created_at for event logging
    public $timestamps = false;

    protected $fillable = [
        'ip_address',
        'user_agent',
        'url',
        'referer',
        'payload',
    ];

    protected $casts = [
        'payload' => 'array',
        'created_at' => 'datetime',
    ];

    /**
     * Set the creation date on record start.
     */
    protected static function booted()
    {
        static::creating(function ($model) {
            $model->created_at = $model->freshTimestamp();
        });
    }
}