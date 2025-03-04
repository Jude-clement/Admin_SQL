<?php

namespace App\Exceptions;
use Illuminate\Auth\AuthenticationException;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;

class Handler extends ExceptionHandler
{
    protected function unauthenticated($request, AuthenticationException $exception)
{
    // Check if the request has an Authorization header
    if (!$request->header('Authorization')) {
        return response()->json([
            // 'success' => false,
            'message' => 'No token provided. Please log in.'
        ], 401);
    }

    // If a token is provided but is invalid
    return response()->json([
        // 'success' => false,
        'message' => 'Invalid or expired token. Please log in again.'
    ], 401);
}
    /**
     * The list of the inputs that are never flashed to the session on validation exceptions.
     *
     * @var array<int, string>
     */
    protected $dontFlash = [
        'current_password',
        'password',
        'password_confirmation',
    ];

    /**
     * Register the exception handling callbacks for the application.
     */
    public function register(): void
    {
        $this->reportable(function (Throwable $e) {
            //
        });
    }
}
