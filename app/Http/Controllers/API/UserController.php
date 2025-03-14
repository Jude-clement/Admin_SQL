<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:sanctum');
        $this->middleware('permission:view')->only(['index', 'show']);
        $this->middleware('permission:add')->only(['store']);
        $this->middleware('permission:update')->only(['update']);
        $this->middleware('permission:delete')->only(['destroy']);
    }

    public function index()
    {
        $users = User::with('roles')->get();
        
        return response()->json([
            'result' => true,
            'message' => 'Users retrieved successfully',
            'data' => $users
        ]);
    }

    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required|string|max:255|regex:/^[A-Za-z0-9_]+$/',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|regex:/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/',
            'role' => 'required|string|in:superadmin,admin,frontoffice',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'result' => false,
                'message' => 'Validation errors',
                'errors' => $validator->errors()
            ], 422);
        }

        $user = User::create([
            'username' => $request->username,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        // Assign role
        $user->assignRole($request->role);

        return response()->json([
            'result' => true,
            'message' => 'User created successfully',
            'data' => $user->load('roles')
        ], 201);
    }

    public function show($id)
    {
        $user = User::with('roles')->find($id);
        
        if (!$user) {
            return response()->json([
                'result' => false,
                'message' => 'User not found',
            ], 404);
        }

        return response()->json([
            'result' => true,
            'message' => 'User retrieved successfully',
            'data' => $user
        ]);
    }

    public function update(Request $request, $id)
    {
        $user = User::find($id);
        
        if (!$user) {
            return response()->json([
                'result' => false,
                'message' => 'User not found',
            ], 404);
        }

        $validator = Validator::make($request->all(), [
            'username' => 'sometimes|string|max:255',
            'email' => 'sometimes|string|email|max:255|unique:users,email,' . $user->id,
            'password' => 'sometimes|string|min:8',
            'role' => 'sometimes|string|in:superadmin,admin,frontoffice',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'result' => false,
                'message' => 'Validation errors',
                'errors' => $validator->errors()
            ], 422);
        }

        if ($request->has('username')) {
            $user->username = $request->username;
        }
        
        if ($request->has('email')) {
            $user->email = $request->email;
        }
        
        if ($request->has('password')) {
            $user->password = Hash::make($request->password);
        }
        
        $user->save();

        // Update role if provided
        if ($request->has('role')) {
            // Remove old roles
            $user->syncRoles([]);
            // Assign new role
            $user->assignRole($request->role);
        }

        return response()->json([
            'result' => true,
            'message' => 'User updated successfully',
            'user' => $user,
            // 'data' => $user->load('roles')
        ]);
    }

    public function destroy($id)
    {
        $user = User::find($id);
        
        if (!$user) {
            return response()->json([
                'result' => false,
                'message' => 'User not found',
            ], 404);
        }

        // Prevent self-deletion
        if (auth()->id() == $id) {
            return response()->json([
                'result' => false,
                'message' => 'You cannot delete yourself',
            ], 403);
        }

        $user->delete();

        return response()->json([
            'result' => true,
            'message' => 'User deleted successfully',
        ]);
    }
}