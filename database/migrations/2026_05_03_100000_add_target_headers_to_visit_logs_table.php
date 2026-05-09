<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('visit_logs', function (Blueprint $table) {
            /**
             * We use JSON to store a flexible set of headers defined in config.
             * No index is required as this data is primarily for post-analysis 
             * and not for direct lookups in high-frequency queries.
             */
            $table->json('target_headers')
                ->nullable()
                ->after('user_agent')
                ->comment('Technical headers (Client Hints, Fetch Metadata) for bot detection');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('visit_logs', function (Blueprint $table) {
            $table->dropColumn('target_headers');
        });
    }
};