<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     * * @return void
     */
    public function up(): void
    {
        Schema::table('visit_logs', function (Blueprint $table) {
            // Adding anonymized_at column to track when the IP was masked.
            // Using nullable timestamp to allow unmasked logs.
            // Added index to optimize batch processing queries.
            $table->timestamp('anonymized_at')->nullable()->after('processed_at')->index();
        });
    }

    /**
     * Reverse the migrations.
     * * @return void
     */
    public function down(): void
    {
        Schema::table('visit_logs', function (Blueprint $table) {
            $table->dropIndex(['anonymized_at']);
            $table->dropColumn('anonymized_at');
        });
    }
};