<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class AuthController extends BaseController
{
    public function register(Request $request) {
        $input = $request->all();
        $user = User::create($input);
        return $this->sendResponse('', 'Sikeres regisztráció!');
    }
}
