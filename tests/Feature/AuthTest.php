<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\WithFaker;
use Laravel\Sanctum\Sanctum;
use Tests\TestCase;

class AuthTest extends TestCase
{
    use RefreshDatabase;
    /**
     * A basic feature test example.
     *
     * @return void
     */
    public function test_register()
    {
        $response = $this->json('post', '/auth/register', [
            'name' => 'test',
            'email' => 'test@example.com',
            'password' => 'Password123',
            'password_confirmation' => 'Password123'
        ]);

//        $response->dump();
        $response->assertStatus(200);
    }

    public function test_login()
    {
        $user = User::factory()->create();
        $response = $this->json('post', '/auth/login', [
            'email' => $user->email,
            'password' => 'password',
        ]);

//        $response->dump();
        $response->assertStatus(200);
    }

    public function test_logout()
    {
        Sanctum::actingAs(
            User::factory()->create()
        );

        $response = $this->json('post', '/auth/logout');

//        $response->dump();
        $response->assertStatus(200);
    }
}
