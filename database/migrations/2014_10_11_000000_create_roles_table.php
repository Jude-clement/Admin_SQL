<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateRolesTable extends Migration
{
    public function up()
    {
        Schema::create('roles', function (Blueprint $table) {
            $table->id(); // Primary key
            $table->string('name')->unique(); // Role name (e.g., super admin, admin, front office)
            $table->json('permissions')->nullable(); // Store permissions as JSON
            $table->timestamps(); // Created at and updated at timestamps
        });
    }

    public function down()
    {
        Schema::dropIfExists('roles'); // Drop the table if the migration is rolled back
    }
}