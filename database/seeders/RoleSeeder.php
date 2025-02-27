<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Role;

class RoleSeeder extends Seeder
{
    public function run()
    {
        Role::create([
            'name' => 'superadmin',
            'permissions' => json_encode(['add', 'delete', 'update', 'view']),
        ]);

        Role::create([
            'name' => 'admin',
            'permissions' => json_encode(['add', 'view']),
        ]);

        Role::create([
            'name' => 'frontoffice',
            'permissions' => json_encode(['view']),
        ]);
    }
}