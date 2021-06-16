<?php

namespace App\Jobs;

use App\Models\User;
use App\Notifications\SignUpMailNotification;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;

class SendVerificationEmailJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * @var User
     */
    private $user;
    private $otp;

    /**
     * Create a new job instance.
     *
     * @return void
     */
    public function __construct(User $user, $otp)
    {
        $this->user = $user;
        $this->otp = $otp;
    }

    /**
     * Execute the job.
     *
     * @return void
     */
    public function handle()
    {
        $url = env('SPA_URL', 'localhost:3000').'/email/verify?email='.$this->user['email'].'&otp='.$this->otp;
        $this->user
            ->notify(new SignUpMailNotification($url));
    }
}
