<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;

class AuthController extends BaseController
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => ['required', 'email', 'unique:App\Models\User,email'],
            'password' => 'required',
            'passwordConfirmation' => 'required | same:password',
            'role' => ['required', 'integer'],
        ], [
            'name.required' => 'Kötelező kitölteni!',
            'email.required' => 'Kötelező kitölteni!',
            'email.email' => 'Hibás email cím!',
            'email.unique' => 'Az email cím már létezik!',
            'password.required' => 'Kötelező kitölteni!',
            'passwordConfirmation.required' => 'Kötelező kitölteni!',
            'passwordConfirmation.same' => 'A két jelszó nem egyforma!',
            'role.required' => 'Kötelező kitölteni!',
            'role.integer' => 'Csak szám lehet!',
        ]);

        if ($validator->fails()) {
            return $this->sendError('Bad Request', $validator->errors(), 400);
        }

        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);

        $success['name'] = $user->name;
        $success['token'] = $user->createToken('Secret')->plainTextToken;

        return $this->sendResponse($success, 'Sikeres regisztráció!');
    }

    public function login(Request $request)
    {
        if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            $user = Auth::user();
            $success['name'] = $user->name;
            $success['id'] = $user->id;
            $success['role'] = $user->role;
            $success['token'] = $user->createToken('Secret')->plainTextToken;

            return $this->sendResponse($success, 'Sikeres bejelentkezés!');
        } else {
            return $this->sendError('Unauthorized', ['error' => 'Sikertelen bejelentkezés!'], 401);
        }
    }

    public function logout()
    {
        auth()->user()->tokens()->delete();
        return $this->sendResponse('', 'Sikeres kijelentkezés!');
    }
}
