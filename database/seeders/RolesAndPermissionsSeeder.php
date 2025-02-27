<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;

class RolesAndPermissionsSeeder extends Seeder
{
    public function run()
    {
        // Reset cached roles and permissions
        app()[\Spatie\Permission\PermissionRegistrar::class]->forgetCachedPermissions();

        // Create permissions
        Permission::create(['name' => 'view']);
        Permission::create(['name' => 'add']);
        Permission::create(['name' => 'update']);
        Permission::create(['name' => 'delete']);

        // Create roles and assign permissions
        $frontofficeRole = Role::create(['name' => 'frontoffice']);
        $frontofficeRole->givePermissionTo('view');

        $adminRole = Role::create(['name' => 'admin']);
        $adminRole->givePermissionTo(['view', 'add']);

        $superadminRole = Role::create(['name' => 'superadmin']);
        $superadminRole->givePermissionTo(['view', 'add', 'update', 'delete']);
    }
}