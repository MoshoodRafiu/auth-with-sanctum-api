<?php

namespace App\Http\Controllers;

use App\Jobs\SendVerificationEmailJob;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:sanctum')->except('login', 'register', 'sendPasswordResetLink', 'resetPassword');
    }

    public function register(): \Illuminate\Http\JsonResponse
    {
        // Validate request
        $credentials = request(['email', 'name', 'password', 'password_confirmation']);
        $validator = Validator::make($credentials, [
            'email' => ['required', 'email', 'unique:users,email', 'max:255'],
            'name' => ['required', 'unique:users,name', 'max:255'],
            'password' => ['required', 'confirmed', Password::min(8)->mixedCase()->numbers()]
        ]);
        if ($validator->fails()){
            return response()->json(['message' => 'Input validation error', 'errors' => $validator->messages()], 422);
        }
        // Set up data and create user
        $credentials['password'] = Hash::make($credentials['password']);
        $otp = sha1($credentials['email'].time());
        $credentials['email_verification_token'] = Hash::make($otp);
        $credentials['email_verification_token_expiry'] = now()->addHour();
        $user = User::create($credentials);
        // Send email verification email
        SendVerificationEmailJob::dispatch($user, $otp);
        // Log user in
        if (!Auth::attempt(request()->only('email', 'password'))){
            return response()->json(['message' => 'Something went wrong'], 400);
        }
        return $this->returnDataWithTokenOrUser($user, 'Registration Successful');
    }

    private function returnDataWithTokenOrUser($user, $msg): \Illuminate\Http\JsonResponse
    {
        $token = $user->createToken(request()->get('token_name') ?? 'app')->plainTextToken;
        return response()->json(['message' => $msg, 'data' => ['user' => $user, 'token' => $token]]);
    }
}
