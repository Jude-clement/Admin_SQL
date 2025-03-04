<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\AuthController;
use App\Http\Controllers\API\UserController;

// Public routes
// Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);
Route::post('/refresh', [AuthController::class, 'refresh']); // Add this new route

// Protected routes
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/profile', [AuthController::class, 'profile']); //shows current logged in user's profile
    
    // User management routes
    Route::apiResource('users', UserController::class); //for CRUD operations on users
});






///////////


// <?php

// use Illuminate\Support\Facades\Route;
// use App\Http\Controllers\API\AuthController;
// use App\Http\Controllers\API\ResourceController;

// // Public routes
// Route::post('/register', [AuthController::class, 'register']);
// Route::post('/login', [AuthController::class, 'login']);

// // Protected routes
// Route::middleware('auth:sanctum')->group(function () {
//     Route::post('/logout', [AuthController::class, 'logout']);
//     Route::get('/profile', [AuthController::class, 'profile']);
    
//     // Resource routes with permission middleware
//     Route::get('/resources', [ResourceController::class, 'index'])->middleware('permission:view');
//     Route::post('/resources', [ResourceController::class, 'store'])->middleware('permission:add');
//     Route::get('/resources/{id}', [ResourceController::class, 'show'])->middleware('permission:view');
//     Route::put('/resources/{id}', [ResourceController::class, 'update'])->middleware('permission:update');
//     Route::delete('/resources/{id}', [ResourceController::class, 'destroy'])->middleware('permission:delete');
// });