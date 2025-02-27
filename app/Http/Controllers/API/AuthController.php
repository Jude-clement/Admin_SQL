<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'username' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8',
            'role' => 'required|string|in:superadmin,admin,frontoffice',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'success' => false,
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
            'success' => true,
            'message' => 'User registered successfully',
            'user' => $user
        ], 201);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);
    
        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => 'Validation errors',
                'errors' => $validator->errors()
            ], 422);
        }
    
        // Check email
        $user = User::where('email', $request->email)->first();
    
        // Check password
        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid credentials',
            ], 401);
        }
    
        // Get user's role and permissions
        $roles = $user->getRoleNames();
        $permissions = $user->getAllPermissions()->pluck('name');
    
        // Create token with abilities based on permissions
        $token = $user->createToken('auth_token', $permissions->toArray())->plainTextToken;
    
        return response()->json([
            'success' => true,
            'message' => 'Login successful',
            'user' => $user,
            'roles' => $roles,
            'permissions' => $permissions,
            'token' => $token,
            'token_type' => 'Bearer',
        ]);
    }

    public function logout(Request $request)
    {
        // Revoke the token that was used to authenticate the current request
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'success' => true,
            'message' => 'Successfully logged out',
        ]);
    }

    public function profile(Request $request)
    {
        $user = $request->user();
        $roles = $user->getRoleNames();
        $permissions = $user->getAllPermissions()->pluck('name');

        return response()->json([
            'success' => true,
            'user' => $user,
            'roles' => $roles,
            'permissions' => $permissions,
        ]);
    }
}