<?php

namespace Oleant\VisitAnalytics\Database\Migrations;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Class CreateBotnetFingerprintsTable
 * * This table stores identified botnet signatures based on User-Agent patterns.
 * It allows the system to perform high-speed lookups during the request cycle.
 */
return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::dropIfExists('botnet_fingerprints');
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
    
        Schema::create('botnet_fingerprints', function (Blueprint $table) {
            $table->id();
            
            $table->char('ua_hash', 64)->unique();
            
            $table->text('user_agent');
            
            $table->integer('hits_count')->default(0);
            
            $table->integer('unique_ips_count')->default(0);
            
            $table->string('detection_reason')->nullable();
            
            $table->timestamp('detected_at')->nullable();
            $table->timestamp('last_seen_at')->nullable();
            
            $table->boolean('is_active')->default(true)->index();

            $table->timestamps();
        });
    }
};