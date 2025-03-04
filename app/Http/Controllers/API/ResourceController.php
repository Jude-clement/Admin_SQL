<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class ResourceController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:sanctum');
        $this->middleware('permission:view')->only(['index', 'show']);
        $this->middleware('permission:add')->only(['store']);
        $this->middleware('permission:update')->only(['update']);
        $this->middleware('permission:delete')->only(['destroy']);
    }

    public function index(Request $request)
    {
        // Your view logic here
        return response()->json([
            'success' => true,
            'message' => 'Resources retrieved successfully',
            'data' => [
                // 'id'    => $request->id,
                'email' => $request->email,
                // Your data here
            ]
        ]);
    }

    public function store(Request $request)
    {
        // Your create logic here
        return response()->json([
            'success' => true,
            'message' => 'Resource created successfully',
            'data' => [
                'name' => $request->name,
                // Your data here
            ]
        ], 201);
    }

    public function show(Request $request, $id)
    {
        // Your show logic here
        return response()->json([
            'success' => true,
            'message' => 'Resource retrieved successfully',
            'data' => [
                'id' => $id,
                // Other data
            ]
        ]);
    }

    public function update(Request $request, $id)
    {
        // Your update logic here
        return response()->json([
            'success' => true,
            'message' => 'Resource updated successfully',
            'data' => [
                'id' => $id,
                // Other data
            ]
        ]);
    }

    public function destroy(Request $request, $id)
    {
        // Your delete logic here
        return response()->json([
            'success' => true,
            'message' => 'Resource deleted successfully',
        ]);
    }
}


//this page is not needed