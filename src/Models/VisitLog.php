<?php

namespace Oleant\VisitAnalytics\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * @property string $ip_address
 * @property string $user_agent
 * @property string $url
 * @property string $referer
 * @property array $payload
 * @property \DateTime $processed_at
 * @property int $bot_score
 * @property bool $is_bot
 * @property \DateTime $created_at
 */
class VisitLog extends Model
{
    // We handle created_at manually in booted()
    public $timestamps = false;

    protected $fillable = [
        'ip_address',
        'user_agent',
        'url',
        'referer',
        'payload',
        // ADD THESE NEW FIELDS:
        'processed_at',
        'bot_score',
        'is_bot',
    ];

    protected $casts = [
        'payload'      => 'array',
        'processed_at' => 'datetime',
        'created_at'   => 'datetime',
        'bot_score'    => 'integer',
        'is_bot'       => 'boolean',
    ];

    /**
     * Set the creation date on record start.
     */
    protected static function booted()
    {
        static::creating(function ($model) {
            // Ensure created_at is set if not provided
            if (!$model->created_at) {
                $model->created_at = $model->freshTimestamp();
            }
        });
    }
}