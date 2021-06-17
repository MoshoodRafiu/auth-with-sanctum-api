<?php

namespace App\Http\Controllers;

use App\Jobs\SendPasswordResetLink;
use App\Jobs\SendVerificationEmailJob;
use App\Models\User;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
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
            return response()->json([
                'message' => 'Input validation error',
                'errors' => $validator->messages()
            ], 422);
        }
        // Set up data and create user
        $credentials['password'] = Hash::make($credentials['password']);
        $otp = sha1($credentials['email'].time());
        $credentials['email_verification_token'] = Hash::make($otp);
        $credentials['email_verification_token_expiry'] = now()->addHour();
        $user = User::create($credentials);
        // Send email verification email and send response
        SendVerificationEmailJob::dispatch($user, $otp);
        return $this->returnDataWithTokenAndData($user, 'Registration Successful');
    }

    public function login(): \Illuminate\Http\JsonResponse
    {
        // Validate request
        $credentials = request(['email', 'password']);
        $validator = Validator::make($credentials, [
            'email' => ['required', 'email'],
            'password' => ['required']
        ]);
        if ($validator->fails()){
            return response()->json([
                'message' => 'Input validation error',
                'errors' => $validator->messages()
            ], 422);
        }
        if (!Auth::attempt(request()->only('email', 'password'))){
            return response()->json(['message' => 'Invalid login credentials'], 400);
        }
        $user = User::query()->where('email', request()->get('email'))->first();
        return $this->returnDataWithTokenAndData($user, 'Login Successful');
    }

    public function logout(): \Illuminate\Http\JsonResponse
    {
        \request()->user()->currentAccessToken()->delete();
        return response()->json(['message' => 'Logout successful']);
    }

    public function sendPasswordResetLink(): \Illuminate\Http\JsonResponse
    {
        $validator = Validator::make(\request()->all(), [
            'email' => ['required', 'email']
        ]);
        if ($validator->fails()){
            return response()->json([
                'message' => 'Input validation error',
                'errors' => $validator->messages()
            ], 422);
        }
        if (!User::query()->where('email', \request()->only('email'))->first())
            return response()->json(['message' => "We couldn't find a user with this email address"], 404);
        SendPasswordResetLink::dispatch(\request()->only('email'));
        return response()->json(['message' => 'We have emailed you a password reset link']);
    }

    public function resetPassword(): \Illuminate\Http\JsonResponse
    {
        $validator = Validator::make(\request()->all(), [
            'token' => ['required'],
            'email' => ['required', 'email'],
            'password' => ['required', 'confirmed', Password::min(8)->mixedCase()->numbers()]
        ]);
        if ($validator->fails()){
            return response()->json([
                'message' => 'Input validation error',
                'errors' => $validator->messages()
            ], 422);
        }
        $status = \Illuminate\Support\Facades\Password::reset(
            \request()->only('email', 'password', 'password_confirmation', 'token'),
            function ($user, $password) {
                $user->forceFill([
                    'password' => Hash::make($password)
                ])->setRememberToken(Str::random(60));

                $user->save();

                event(new PasswordReset($user));
                Auth::attempt(\request()->only('email', 'password'));
            }
        );

        if (!$status == \Illuminate\Support\Facades\Password::PASSWORD_RESET) {
            response()->json(['message' => __($status)], 400);
        }
        $user = User::query()->where('email', \request()->only('email'))->first();
        return $this->returnDataWithTokenAndData($user, __($status));
    }

    private function returnDataWithTokenAndData($user, $msg): \Illuminate\Http\JsonResponse
    {
        $token = $user->createToken(request()->get('token_name') ?? 'app')->plainTextToken;
        return response()->json(['message' => $msg, 'data' => ['user' => $user, 'token' => $token]]);
    }
}
