<?php

/*
|--------------------------------------------------------------------------
| Application Routes
|--------------------------------------------------------------------------
|
| Here is where you can register all of the routes for an application.
| It's a breeze. Simply tell Laravel the URIs it should respond to
| and give it the controller to call when that URI is requested.
|
*/

use App\Http\Controllers\Controller;

Route::get('/', function () {
  return view('welcome');
});

Route::group(['prefix' => 'server'], function () {
  Route::get('authorize', 'ServerController@getAuthorize');
  Route::get('token', 'ServerController@getToken');
  Route::get('results', 'ServerController@getResults');
});

Route::group(['prefix' => 'client'], function () {
  Route::get('tests', 'ClientController@getTests');
});
