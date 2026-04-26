<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations to update visit_logs with bot detection features and performance indexes.
     */
    public function up(): void
    {
        Schema::table('visit_logs', function (Blueprint $table) {
            // 1. Add processing fields after the payload
            // We explicitly name the indexes to ensure reliable rollbacks
            $table->timestamp('processed_at')->nullable()->after('payload')->index('idx_visit_processed_at');
            $table->unsignedTinyInteger('bot_score')->default(0)->after('processed_at');
            $table->boolean('is_bot')->default(false)->after('bot_score')->index('idx_visit_is_bot');

            /**
             * 2. Composite index for behavioral analysis performance.
             * This is the "engine" that speeds up calculateRateScore and calculatePathScore.
             * It allows the database to filter by IP and Time Window simultaneously.
             */
            $table->index(['ip_address', 'created_at'], 'idx_bot_analysis_lookup');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('visit_logs', function (Blueprint $table) {
            /**
             * When dropping indexes by their explicit names, we ensure 
             * compatibility even if the auto-generation logic changes.
             */
            $table->dropIndex('idx_bot_analysis_lookup');
            $table->dropIndex('idx_visit_processed_at');
            $table->dropIndex('idx_visit_is_bot');
            
            // Drop columns
            $table->dropColumn(['processed_at', 'bot_score', 'is_bot']);
        });
    }
};