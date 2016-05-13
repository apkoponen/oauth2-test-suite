<!DOCTYPE html>
<html>

<head>
  <title>OAuth 2.0 Test Suite</title>

  <link href="https://fonts.googleapis.com/css?family=Lato:400,700" rel="stylesheet" type="text/css">

  <style>
    html,
    body {
      height: 100%;
    }

    body {
      margin: 0;
      padding: 0;
      width: 100%;
      font-weight: 400;
      font-family: 'Lato';
    }

    h1,
    h2,
    h3,
    h4,
    h5,
    h6 {
      font-weight: 700;
    }

    .container {
      max-width: 960px;
      margin: 0 auto;
    }

    .box {
      padding: 20px;
    }

    .box h2 {
      margin-top: 0;
    }

    .test-section {
      margin-bottom: 20px;
    }

    .test {
      margin-bottom: 1px;
    }

    .test-case {
      margin-bottom: 1px;
    }

    .pass {
      background-color: #4CAF50;
      color: #ffffff;
    }

    .fail {
      background-color: #FFC107;
    }

    .status {
        float: right;
        text-transform: uppercase;
    }

    .nav {
      margin: 30px 0;
    }

    .nav ul {
      list-style: none;
      padding: 0;
      margin: 0;
    }

    .nav ul li {
      display: inline-block;
      margin-right: 5px;
      margin-bottom: 5px;
    }

    .nav ul li a {
      line-height: 40px;
      transition: All 0.25s ease;
      background: #333;
      padding: 0 20px;
      color: #fff;
      text-decoration: none;
      display: inline-block;
    }

    .nav ul li a:hover {
      background: #000;
    }

    .error {
      padding: 20px;
      background: #D32F2F;
      color: #fff;
      margin-bottom: 20px;
    }

    .error h3 {
      margin-top: 0;
    }
  </style>
</head>

<body>
  <div class="container">
    <div class="content">
      <div class="nav">
        <ul>
          @foreach($test_nav_items as $nav_item)
          <li><a target="_blank" href="?test={{ $nav_item->test }}">{{ $nav_item->name }}</a></li>
          @endforeach
        </ul>

      </div>
      <h1>Test results</h1>
      
      @if (!empty($error))
        <div class="error">
          <h3>Test interrupted by an error:</h3>
          {{ $error }}
        </div>
      @endif


      @foreach ($tests as $test)
      <div class="test-section">
        <div class="test box {{ $test->status }}">
          <h2>
              {{ $test->name }}
              <div class="status">{{ $test->status }}</status>
          </h2>
          <strong>{{ $test->description }}:</strong>
        </div>
        @foreach ($test->cases as $case)
        <div class="test-case box {{ $case->status }}">
            – {{ $case->description }}
            <div class="status">
                {{ $case->status }}
            </div>
        </div>
        @endforeach
      </div>
      @endforeach
    </div>
  </div>
</body>

</html>
