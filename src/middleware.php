<?php
/**
 * Example middleware closure
 *
 * @param  \Psr\Http\Message\ServerRequestInterface $request  PSR7 request
 * @param  \Psr\Http\Message\ResponseInterface      $response PSR7 response
 * @param  callable                                 $next     Next middleware
 *
 * @return \Psr\Http\Message\ResponseInterface
 */
$dotenv = new Dotenv\Dotenv(__DIR__);
$dotenv->load();
$container = $app->getContainer();

$container["jwt"] = function ($container) {
    return new StdClass;
};

$Test = function ($request, $response, $next) {
    $response->getBody()->write('BEFORE');
   
    $response = $next($request, $response);
    $response->getBody()->write('AFTER');

    return $response;
};


$JwtAuthentication=new Tuupola\Middleware\JwtAuthentication([
    "attribute" => "decoded_token_data",
    
    "path" => ["/api"],
    "ignore" => ["/api/login"],
    "secure" => true,
    "relaxed" => ["localhost", "dev.example.com"], // when in deployment must set from localhost to zafora
    "secret" => getenv("SECRET_KEY"),
    "algorithm" => ["HS256"],
    "before"  => function ($request, $arguments) use ($container) {

      

        $container["jwt"] = $arguments["decoded"];
       
    },
    "error" => function ($response, $arguments) {
        $data["status"] = "error";
        $data["message"] = $arguments["message"];
     
        return $response
            ->withHeader("Content-Type", "application/json")
            ->write(json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT));
    }
]);

// $app->add(new \Slim\Middleware\HttpBasicAuthentication([
//     "path" => "/api/login",
//     "users" => [
//         "user" => "password"
//     ]
// ]));

$app->add($JwtAuthentication);
// $decoded = $request->getAttribute("jwt");