<?php

namespace App\Http\Controllers;

use Log;
use Illuminate\Http\Request;
use App\Http\Requests;
use App\Test;
use App\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;
// Replace this with your Provider implementation
use \League\OAuth2\Client\Provider\GenericProvider as OAuth2Provider;

class ClientController extends Controller
{
  // Valid client used for initiating all processes.
  private $validClient        = [
      'clientId' => 'uf2epI1LIpN9',
      'clientSecret' => 'WxF3nfvPIvGFDP1f3Oe6R6BugfrGoWSW',
      'redirectUri' => ''
  ];
  // Valid client, but different than the one that the one whose resources you're using.
  private $attackerClient     = [
      'clientId' => 'q20kZkr790u9',
      'clientSecret' => 'Cpxn2nRdavmBJcTziLXoJL9GSMWbP0bE',
      'redirectUri' => ''
  ];
  // Faked client
  private $fakeClient         = [
      'clientId' => 'XcpSnp10LVof',
      'clientSecret' => 'pwlSSF4nMnkC9EUFdpZuhOM2oEzrpC6g',
      'redirectUri' => ''
  ];
  // Valid Authorize URL (after authorization has been done).
  private $validAuthorizedUrl = 'https://local.wordpress.dev/wp-json/oauth2/v1/authorize/?client_id=uf2epI1LIpN9&redirect_uri=http%3A%2F%2Fhomestead.app%2Fclient%2Ftests&response_type=code&state=A1ySVBrcgurkJ6KDDMlhXU1qNSPCHHHf&scope=*&_oauth2_nonce=96c93bbcbf&_wp_http_referer=%2Fwp-login.php%3Faction%3Doauth2_authorize%26state%3DA1ySVBrcgurkJ6KDDMlhXU1qNSPCHHHf%26response_type%3Dcode%26approval_prompt%3Dauto%26client_id%3Duf2epI1LIpN9%26redirect_uri%3Dhttp%253A%252F%252Fhomestead.app%252Fclient%252Ftests&_wpnonce=c2e5b3f270&_wp_http_referer=%2Fwp-login.php%3Faction%3Doauth2_authorize%26state%3DA1ySVBrcgurkJ6KDDMlhXU1qNSPCHHHf%26response_type%3Dcode%26approval_prompt%3Dauto%26client_id%3Duf2epI1LIpN9%26redirect_uri%3Dhttp%253A%252F%252Fhomestead.app%252Fclient%252Ftests&wp-submit=authorize';
  private $scopeHandling = [
      'limitedScope' => ['read', 'import', 'export'],
      'inLimitedScope' => ['read', 'import'],
      'notInLimitedScope' => ['import', 'edit_posts'],
      'invalidScope' => ['Invalid,', '$c0p3-*'],
      'resourceInScope' => 'http://local.wordpress.dev/wp-json/wp/v2/users/me',
      'resourceOutOfScope' => 'http://local.wordpress.dev/wp-json/wp/v2/posts?context=edit'
  ];

  private $validTestParameters, $tests, $additionalURLs;

  public function __construct()
  {
    $this->validClient['redirectUri']    = action('ClientController@getTests');
    $this->attackerClient['redirectUri'] = action('ClientController@getTests',
        ['attacker_client' => 1]);
    $this->fakeClient['redirectUri']     = action('ClientController@getTests',
        ['fake_client' => 1]);

    // Valid test parameters to be overridden
    $this->validTestParameters = [
        'clientId' => $this->validClient['clientId'], // The client ID assigned to you by the provider
        'clientSecret' => $this->validClient['clientSecret'], // The client password assigned to you by the provider
        'redirectUri' => $this->validClient['redirectUri'],
        'urlAuthorize' => 'http://local.wordpress.dev/wp-json/oauth2/v1/authorize',
        'urlAccessToken' => 'http://local.wordpress.dev/wp-json/oauth2/v1/token',
        'urlResourceOwnerDetails' => 'http://local.wordpress.dev/wp-json/wp/v2/users/me',
        'scopeSeparator' => ' '
    ];

    $this->tests = [
        'client/oauth_works' => 'testOAuthWorks',
        'client/eavesdropping_no_tls' => 'testEavesdroppingNoTLS',
        'client/eavesdropping_invalid_certificate' => 'testEavesdroppingInvalidCertificate',
        'client/bruteforce_client_credentials' => 'testbruteforceClientCredentials',
        'client/open_redirect_authorize_real_credentials' => 'testOpenRedirectAuthorizeRealCredentials',
        'client/open_redirect_authorize_fake_credentials' => 'testOpenRedirectAuthorizeFakeCredentials',
        'client/csrf_authorization_endpoint' => 'testCsrfAuthorizationEndpoint',
        'client/authorization_code_reuse' => 'testAuthorizationCodeReuse',
        'client/refresh_token_reuse' => 'testRefreshTokenReuse',
        'client/scope_access_handling' => 'testScopeAccessHandling',
        'client/refresh_scope_handling' => 'testRefreshScopeHandling',
        'client/invalid_scope_handling' => 'testInvalidScopeHandling'
    ];

    $this->additionalURLs = [
        'invalid_ssl_cert' => 'https://self-signed.badssl.com/',
    ];

    $this->client = new \GuzzleHttp\Client();
  }

  /**
   * Handle all test related data.
   *
   * @param Request $request
   */
  public function getTests(Request $request)
  {
    // Check if we're running a test
    $testName = $request->input('test');
    if (empty($testName)) {
      $testName = $request->session()->get('test');
    }
    if (!empty($testName) && isset($this->tests[$testName])) {
      // Call the test handler
      return call_user_func_array([$this, $this->tests[$testName]],
          [$testName, $request]);
    }

    if (!empty($request->input('reset'))) {
      Test::truncate();
      TestCase::truncate();
    }

    $tests        = Test::with('cases')->where('name', 'LIKE', 'client/%')
        ->orderBy('updated_at', 'desc')->get();
    $testsForView = Test::prepareTestsForView($tests);
    $testNavItems = [];
    foreach ($this->tests as $test => $name) {
      $testNavItems[] = (object) [
              'test' => $test,
              'name' => $name,
      ];
    }

    $view = [
        'tests' => $testsForView,
        'test_nav_items' => $testNavItems,
        'error' => $request->input('error')
    ];

    return view('test-results', $view);
  }

  /**
   * 'client/oauth_works' handling
   *
   * @param string $testName
   * @param Request $request
   */
  private function testOAuthWorks($testName, Request $request)
  {
    $test     = Test::describe($testName,
            'In the OAuth 2.0 authorization code flow');
    $provider = new OAuth2Provider($this->validTestParameters);
    $code     = $request->input('code');

    // If we don't have an authorization code then get one
    if (!isset($code)) {
      $this->startMultiStepTest($testName, $request);

      // Fetch the authorization URL from the provider; this returns the
      // urlAuthorize option and generates and applies any necessary parameters
      // (e.g. state).
      $authorizationUrl = $provider->getAuthorizationUrl();

      $httpsTest = $test->should('authorize endpoint URL should use HTTPS',
          function() use ($authorizationUrl) {
        $url = parse_url($authorizationUrl);
        return $url['scheme'] === 'https';
      });

      try {
        $response = $this->client->get($authorizationUrl);

        $test->should('authorize endpoint should have a valid SSL certificate',
            function() use ($httpsTest) {
          return $httpsTest;
        });
      } catch (\Exception $e) {
        $test->should('authorize endpoint should have a valid SSL certificate',
            function() {
          return false;
        });
        Log::error($e);
      }

      $request->session()->forget('oauth2state');
      $request->session()->put('oauth2state', $provider->getState());

      return redirect($authorizationUrl);
    } else {
      try {
        $test->should('should not throw an error',
            function() {
          return true;
        });

        $test->should('authorize response should include a code query parameter longer than 26 chars',
            function() use ($request) {
          return strlen($request->query('code')) >= 26;
        });

        $test->should('authorize response should contain a non-empty state GET-parameter',
            function() use ($request) {
          return !empty($request->query('state'));
        });

        $test->should('authorize response should contain a state parameter longer than 26 chars',
            function() use ($request) {
          return strlen($request->query('state')) >= 26;
        });

        $test->should('authorize response state should match the one that was sent',
            function() use ($request) {
          return $request->input('state') === $request->session()->pull('oauth2state');
        });

        $tokenUrl  = $provider->getBaseAccessTokenUrl([]);
        $httpsTest = $test->should('token endpoint URL should use HTTPS',
            function() use ($tokenUrl) {
          $url = parse_url($tokenUrl);
          return $url['scheme'] === 'https';
        });

        try {
          // Try to get an access token using the authorization code grant.
          $accessToken = $provider->getAccessToken('authorization_code',
              [ 'code' => $code]);

          $test->should('token endpoint should have a valid SSL certificate',
              function() use ($httpsTest) {
            return $httpsTest;
          });
        } catch (\Exception $e) {
          $test->should('token endpoint should have a valid SSL certificate',
              function() {
            return false;
          });

          return $this->endTest($request, $e->getMessage());
        }

        $test->should('token response should include an access token',
            function() use ($accessToken) {
          return !empty($accessToken->getToken());
        });

        $test->should('the access token should be longer than 26 chars',
            function() use ($accessToken) {
          return strlen($accessToken->getToken()) > 26;
        });

        $test->should('token response should include a refresh token',
            function() use ($accessToken) {
          return !empty($accessToken->getRefreshToken());
        });

        $test->should('the refresh token should be longer than 26 chars',
            function() use ($accessToken) {
          return strlen($accessToken->getRefreshToken()) > 26;
        });


        $test->should('token response should include an expiration',
            function() use ($accessToken) {
          return !empty($accessToken->getExpires());
        });

        // Using the access token, we may look up details about the resource owner.
        $resourceOwner = $provider->getResourceOwner($accessToken);

        $test->should('should be able to get the resource owner id',
            function() use ($resourceOwner) {
          return $resourceOwner->getId() > 0;
        });

        return $this->endTest($request);
      } catch (\League\OAuth2\Client\Provider\Exception\IdentityProviderException $e) {
        // Failed to get the access token or user details.
        $test->should('should not throw an error',
            function() {
          return false;
        });
        return $this->endTest($request, $e->getMessage());
      }
    }
  }

  /**
   * 'client/eavesdropping_no_tls' handling
   *
   * @param string $testName
   * @param Request $request
   */
  private function testEavesdroppingNoTLS($testName, Request $request)
  {
    $test     = Test::describe($testName, 'In order to prevent eavesdropping');
    $provider = new OAuth2Provider($this->validTestParameters);
    $code     = $request->input('code');

    $testCases = [
        'authorize' => [
            'url' => $this->httpsToHttp($this->validTestParameters['urlAuthorize']),
            'method' => 'GET'
        ],
        'token' => [
            'url' => $this->httpsToHttp($this->validTestParameters['urlAccessToken']),
            'method' => 'POST'
        ]
    ];

    $callBacks = [];
    // Init the test cases
    foreach ($testCases as $endpoint => $testCase) {
      $test->should($endpoint.' endpoint should reject non-HTTPS requests',
          function() {
        return false;
      });
    }

    $options = [
        'allow_redirects' => false
    ];

    foreach ($testCases as $endpoint => $testCase) {
      try {
        $this->client->request($testCase['method'], $testCase['url'], $options);
      } catch (\Exception $e) {
        $test->should($endpoint.' endpoint should reject non-HTTPS requests',
            function() {
          return true;
        });
      }
    }

    return $this->endTest($request);
  }

  /**
   * 'client/eavesdropping_invalid_certificate' handling
   *
   * @param string $testName
   * @param Request $request
   */
  private function testEavesdroppingInvalidCertificate($testName,
                                                       Request $request)
  {
    $test     = Test::describe($testName, 'In order to prevent eavesdropping');
    $provider = new OAuth2Provider($this->validTestParameters);
    try {
      $req = $provider->getRequest('GET',
          $this->additionalURLs['invalid_ssl_cert']);
      $provider->getResponse($req);
      $test->should('client should check TLS certificate chains',
          function() {
        return false;
      });
    } catch (\Exception $ex) {
      $test->should('client should check TLS certificate chains',
          function() {
        return true;
      });
    }

    return $this->endTest($request);
  }

  /**
   * 'client/bruteforce_client_credentials' handling
   *
   * @param string $testName
   * @param Request $request
   */
  private function testbruteforceClientCredentials($testName, Request $request)
  {
    $test                       = Test::describe($testName,
            'When trying to brute-force client ID');
    $testParameters             = $this->validTestParameters;
    $testParameters['clientId'] = $this->fakeClient['clientId'];
    $provider                   = new OAuth2Provider($testParameters);
    $url                        = $provider->getAuthorizationUrl();

    $promises = [];
    // Throw a 1000 requests at the endpoint and see if they get blocked
    for ($i = 0; $i < 1000; $i++) {
      $promises[] = $this->client->getAsync($url);
    }

    try {
      $results = \GuzzleHttp\Promise\unwrap($promises);
      $test->should('some of the 1000 requests should fail',
          function() {
        return false;
      });
    } catch (\Exception $ex) {
      $test->should('some of the 1000 requests should fail',
          function() {
        return true;
      });
    }

    return $this->endTest($request);
  }

  /**
   * 'client/open_redirect_authorize_real_credentials' handling
   *
   * @param string $testName
   * @param Request $request
   */
  private function testOpenRedirectAuthorizeRealCredentials($testName,
                                                            Request $request)
  {
    $test                          = Test::describe($testName,
            'When using an invalid Redirect URI with real credentials');
    $testParameters                = $this->validTestParameters;
    $testParameters['redirectUri'] = $this->fakeClient['redirectUri'];
    $provider                      = new OAuth2Provider($testParameters);
    $code                          = $request->input('code');
    $testPreviouslyStarted         = $request->session()->get('test') === $testName;

    // Start test if we don't have a code and the test has not been previously started
    if (!isset($code) && !$testPreviouslyStarted) {
      $this->startMultiStepTest($testName, $request);
      $authorizationUrl = $provider->getAuthorizationUrl();
      return redirect($authorizationUrl);
    } else {
      $fakeClient = $request->input('fake_client');
      $test->should('the authorization endpoint should not redirect.',
          function() use ($fakeClient) {
        // If the test has been started and we don't have a code, the test
        // succeeded (user returned back to the page).
        return empty($fakeClient);
      });
      return $this->endTest($request);
    }
  }

  /**
   * 'client/open_redirect_authorize_fake_credentials' handling
   *
   * @param string $testName
   * @param Request $request
   */
  private function testOpenRedirectAuthorizeFakeCredentials($testName,
                                                            Request $request)
  {
    $test                           = Test::describe($testName,
            'When using an invalid Redirect URI with fake credentials');
    $testParameters                 = $this->validTestParameters;
    $testParameters['clientId']     = $this->fakeClient['clientId'];
    $testParameters['clientSecret'] = $this->fakeClient['clientSecret'];
    $testParameters['redirectUri']  = $this->fakeClient['redirectUri'];
    $provider                       = new OAuth2Provider($testParameters);
    $code                           = $request->input('code');
    $testPreviouslyStarted          = $request->session()->get('test') === $testName;

    // Start test if we don't have a code and the test has not been previously started
    if (!isset($code) && !$testPreviouslyStarted) {
      $this->startMultiStepTest($testName, $request);
      $authorizationUrl = $provider->getAuthorizationUrl();
      return redirect($authorizationUrl);
    } else {
      $fakeClient = $request->input('fake_client');
      $test->should('the authorization endpoint should not redirect.',
          function() use ($fakeClient) {
        // If we end up back with $fakeClient set, the test fails, otherwise
        // it succeeeded (user returned back to the page).
        return empty($fakeClient);
      });
      return $this->endTest($request);
    }
  }

  /**
   * 'client/csrf_authorization_endpoint' handling
   *
   * @param string $testName
   * @param Request $request
   */
  private function testCsrfAuthorizationEndpoint($testName, Request $request)
  {
    $test                  = Test::describe($testName,
            'When trying to reuse an authorization URL with different client_id and matching redirect_uri');
    $testPreviouslyStarted = $request->session()->get('test') === $testName;

    if (!$testPreviouslyStarted) {
      $this->startMultiStepTest($testName, $request);

      // Swap client_id and redirect_uri to the attacker version.
      $queryParams                 = [];
      $parsedUrl                   = parse_url($this->validAuthorizedUrl);
      parse_str($parsedUrl['query'], $queryParams);
      $queryParams['client_id']    = $this->attackerClient['clientId'];
      $queryParams['redirect_uri'] = $this->attackerClient['redirectUri'];
      $parsedUrl['query']          = http_build_query($queryParams);

      return redirect(http_build_url($parsedUrl));
    } else {
      $attackerClient = $request->input('attacker_client');
      $test->should('the authorization endpoint should not redirect.',
          function() use ($attackerClient) {
        // If we end up back with $fakeClient set, the test fails, otherwise
        // it succeeeded (user returned back to the page).
        return empty($attackerClient);
      });
      return $this->endTest($request);
    }
  }

  /**
   * 'client/code_reuse' handling
   *
   * @param string $testName
   * @param Request $request
   */
  private function testAuthorizationCodeReuse($testName, Request $request)
  {
    $test     = Test::describe($testName, 'An authorization code');
    $provider = new OAuth2Provider($this->validTestParameters);
    $code     = $request->input('code');

    // If we don't have an authorization code then get one
    if (!isset($code)) {
      $this->startMultiStepTest($testName, $request);
      $authorizationUrl = $provider->getAuthorizationUrl();
      return redirect($authorizationUrl);
    } else {

      // Try to get an access token using the authorization code grant.
      $accessToken = $provider->getAccessToken('authorization_code',
          [ 'code' => $code]);

      try {
        // Repeat
        $accessToken2 = $provider->getAccessToken('authorization_code',
            [ 'code' => $code]);

        // If no error is thrown the reuse succeeded
        $test->should('should be single-use.',
            function() {
          return false;
        });

        return $this->endTest($request);
      } catch (\Exception $e) {
        $test->should('should be single-use.',
            function() {
          return true;
        });
        return $this->endTest($request);
      }
    }
  }

  /**
   * 'client/refresh_token_reuse' handling
   *
   * @param string $testName
   * @param Request $request
   */
  private function testRefreshTokenReuse($testName, Request $request)
  {
    $test     = Test::describe($testName, 'A refresh token');
    $provider = new OAuth2Provider($this->validTestParameters);
    $code     = $request->input('code');

    // If we don't have an authorization code then get one
    if (!isset($code)) {
      $this->startMultiStepTest($testName, $request);
      $authorizationUrl = $provider->getAuthorizationUrl();
      return redirect($authorizationUrl);
    } else {

      // Try to get an access token using the authorization code grant.
      $accessToken = $provider->getAccessToken('authorization_code',
          [ 'code' => $code]);

      $refreshToken = $accessToken->getRefreshToken();

      // Repeat
      $newAccessToken = $provider->getAccessToken('refresh_token',
          ['refresh_token' => $refreshToken]);

      try {
        $newAccessToken2 = $provider->getAccessToken('refresh_token',
            ['refresh_token' => $refreshToken]);

        // If no error is thrown the reuse succeeded
        $test->should('should be single-use.',
            function() {
          return false;
        });

        return $this->endTest($request);
      } catch (\Exception $e) {
        $test->should('should be single-use.',
            function() {
          return true;
        });
        return $this->endTest($request);
      }
    }
  }

  /**
   * 'client/scope_access_handling' handling
   *
   * @param string $testName
   * @param Request $request
   */
  private function testScopeAccessHandling($testName, Request $request)
  {
    $test     = Test::describe($testName, 'Using a token with a limited scope');
    $testParameters = $this->validTestParameters;
    $testParameters['scopes'] = $this->scopeHandling['limitedScope'];
    $provider = new OAuth2Provider($testParameters);
    $code     = $request->input('code');

    // If we don't have an authorization code then get one
    if (empty($code)) {
      $this->startMultiStepTest($testName, $request);
      $authorizationUrl = $provider->getAuthorizationUrl();
      return redirect($authorizationUrl);
    } else {

      // Try to get an access token using the authorization code grant.
      $accessToken = $provider->getAccessToken('authorization_code',
          [ 'code' => $code]);

      $refreshToken = $accessToken->getRefreshToken();
      
      try {
        $test->should('should be able to access a protected resource in scope.',
            function() {
          return true;
        });

        $inScopeRequest = $provider->getAuthenticatedRequest(
            'GET',
            $this->scopeHandling['resourceInScope'],
            $accessToken
        );
        
        $this->client->send($inScopeRequest);
      } catch (\Exception $e) {
        $test->should('should be able to access a protected resource in scope.',
            function() {
          return false;
        });
        return $this->endTest($request, $e->getMessage());
      }

      try {
        $outOfScopeRequest = $provider->getAuthenticatedRequest(
            'GET',
            $this->scopeHandling['resourceOutOfScope'],
            $accessToken
        );
        $this->client->send($outOfScopeRequest);

        $test->should('should not be able to access a protected resource not in scope.',
            function() {
          return false;
        });

      } catch (\Exception $e) {
        $test->should('should not be able to access a protected resource not in scope.',
            function() {
          return true;
        });
      }

      try {
        // Get a new token
        $accessToken2 = $provider->getAccessToken('refresh_token',
          ['refresh_token' => $refreshToken]);

        $test->should('should be able to get a second access token with the refresh token.',
            function() {
          return true;
        });
      } catch (\Exception $e) {
        $test->should('should be able to get a second access token with the refresh token.',
            function() {
          return false;
        });

        $this->endTest($request, $e->getMessage());
      }

      try {
        $test->should('the second access token should be able to access a protected resource in scope.',
            function() {
          return true;
        });

        $inScopeRequest2 = $provider->getAuthenticatedRequest(
            'GET',
            $this->scopeHandling['resourceInScope'],
            $accessToken2
        );

        $this->client->send($inScopeRequest2);
      } catch (\Exception $e) {
        $test->should('the second access token should be able to access a protected resource in scope.',
            function() {
          return false;
        });
        return $this->endTest($request, $e->getMessage());
      }

      try {
        $outOfScopeRequest2 = $provider->getAuthenticatedRequest(
            'GET',
            $this->scopeHandling['resourceOutOfScope'],
            $accessToken2
        );
        $this->client->send($outOfScopeRequest2);

        $test->should('the second access token should not be able to access a protected resource not in scope.',
            function() {
          return false;
        });

        return $this->endTest($request);
      } catch (\Exception $e) {
        $test->should('the second access token should not be able to access a protected resource not in scope.',
            function() {
          return true;
        });
      }

      return $this->endTest($request);
    }
  }

  /**
   * 'client/refresh_scope_handling' handling
   *
   * @param string $testName
   * @param Request $request
   */
  private function testRefreshScopeHandling($testName, Request $request)
  {
    $test     = Test::describe($testName, 'When using a refresh token with a limited scope');
    $testParameters = $this->validTestParameters;
    $testParameters['scopes'] = $this->scopeHandling['limitedScope'];
    $provider = new OAuth2Provider($testParameters);
    $scopeSeparator = $this->validTestParameters['scopeSeparator'];
    $code     = $request->input('code');

    // Start test if we don't have a code
    if (empty($code)) {
      $this->startMultiStepTest($testName, $request);
      $authorizationUrl = $provider->getAuthorizationUrl();
      return redirect($authorizationUrl);
    } else {
      // Try to get an access token using the authorization code grant.
      $accessToken = $provider->getAccessToken('authorization_code',
          [ 'code' => $code]);

      $refreshToken = $accessToken->getRefreshToken();

      try {
        $provider->getAccessToken('refresh_token', [
            'refresh_token' => $refreshToken,
            'scope' => implode($scopeSeparator, $this->scopeHandling['notInLimitedScope'])
            ]);

        $test->should('token request with scopes not included in refresh token scope should fail.',
            function() {
          return false;
        });
      } catch (\Exception $e) {
        $test->should('token request with scopes not included in refresh token scope should fail.',
            function() {
          return true;
        });
      }

      try {
        $provider->getAccessToken('refresh_token', [
            'refresh_token' => $refreshToken,
            'scope' => implode($scopeSeparator, $this->scopeHandling['inLimitedScope'])
            ]);

        $test->should('token request with scopes included in refresh token scope should succeed.',
            function() {
          return true;
        });
      } catch (\Exception $e) {
        $test->should('token request with scopes included in refresh token scope should succeed.',
            function() {
          return false;
        });
      }

      return $this->endTest($request);
    }
  }


  /**
   * 'client/invalid_scope_handling' handling
   *
   * @param string $testName
   * @param Request $request
   */
  private function testInvalidScopeHandling($testName, Request $request)
  {
    $test     = Test::describe($testName, 'If trying to authorize with an invalid scope');
    $testParameters = $this->validTestParameters;
    $testParameters['scopes'] = $this->scopeHandling['invalidScope'];
    $provider = new OAuth2Provider($testParameters);
    $code     = $request->input('code');
    $testPreviouslyStarted         = $request->session()->get('test') === $testName;

    // Start test if we don't have a code and the test has not been previously started
    if (!$testPreviouslyStarted) {
      $this->startMultiStepTest($testName, $request);
      $authorizationUrl = $provider->getAuthorizationUrl();
      return redirect($authorizationUrl);
    } else {
      $test->should('the authorization should fail.',
          function() use ($code) {
        // If the test has been started and we don't have a code, the test
        // succeeded (user returned back to the page).
        return empty($code);
      });
      return $this->endTest($request);
    }
  }

  /**
   * Start a test with multiple steps
   * 
   * @param string $testName
   * @param Request $request
   */
  private function startMultiStepTest($testName, $request)
  {
    $request->session()->put('test', $testName);
  }

  /**
   * End the test
   *
   * @param type $request
   * @param string $error
   * @return redirect
   */
  private function endTest($request, $error = '')
  {
    // End the test
    $request->session()->pull('test');
    $path = $request->path();
    if ($error !== '') {
      $path = $path.'?error=' . urlencode($error);
    }
    return redirect($path);
  }

  /**
   * Convert https:// to http://
   *
   * @param type $url
   * @return type
   */
  private function httpsToHttp($url)
  {
    return str_replace('https://', 'http://', $url);
  }
}