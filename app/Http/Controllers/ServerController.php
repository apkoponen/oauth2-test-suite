<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use App\Http\Requests;
use App\Test;


class ServerController extends Controller
{
    public function getAuthorize(Request $request) {
        $test = Test::describe('server/token_request', 'Token endpoint requests should');
        $test->should('contain a non-empty state GET-parameter', function() use ($request) {
            return !empty($request->query('state'));
        });
        $test->should('contain a state parameter longer than 8 chars', function() use ($request) {
            return (count($request->query('state')) >= 8);
        });
        $test->should('be done over HTTPS', function() use ($request) {
            return $request->secure();
        });
        $queryParams = [
            'code' => 'GuTbShb5K0AHKd3pJngWPW8tGqBDp47i',
            'state' => $request->query('state')
        ];
        $redirect_url = $request->query('redirect_uri') . '?' . http_build_query($queryParams);
        return redirect($redirect_url);
    }

    public function getToken(Request $request) {
        return response()->json(['name' => 'Authorize', 'state' => 'CA']);
    }

    public function getResults(Request $request) {
        $tests = Test::with('cases')->where('name', 'LIKE', 'server/%')->get();
        $testsForView = Test::prepareTestsForView($tests);

        return view('test-results', ['tests' => $testsForView]);
    }
}
