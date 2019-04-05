<?php

if (!isset($_SESSION)) {
    session_start();
}

require_once 'configuration.php';

// require_once 'middleware.php';

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Http\Request;
use Slim\Http\Response;
use \Firebase\JWT\JWT;
// Routes
// $app->get('/', function (Request $request, Response $response, array $args) {
//     $response = "It works!";
//     return $response;
// });

$app->get('/hello', function (Request $request, Response $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    $name = null ;
    //  $usernameValidator = v::alnum()->noWhitespace()->length(1, 15);
    if ($trainingDateValidator->validate($name)) {
        $response->getBody()->write("Hello,", $name);

        return $response;
    } else {
        $response->getBody()->write("error");

    }
});

$app->post('/api/login', function (Request $request, Response $response, array $args) {
    global $pdo;

    $userData = json_decode(file_get_contents('php://input'));
    $username = $userData->{'username'};
    $password = $userData->{'password'};
    // $status = 0;
    

    $query = "SELECT * FROM ekab WHERE username=:username";
    $result = $pdo->prepare($query);
    $result->execute(array(':username' => $username));
    $count = $result->rowCount();
    $user = $result->fetch(PDO::FETCH_BOTH);

    if ($count == 1 && !empty($user)) {

        if ($password == $user[password]) {
            $_SESSION['username'] = $username;
            $_SESSION['success'] = "You are now logged in";
            $message = "successfully logged in";
            if (isset($_SESSION['username'])) {
                $settings = $this->get('settings');
                $token = JWT::encode(['id' => $user->id, 'username' => $user->username], $settings['jwt']['secret'], "HS256");
                $data = array("username" => $username, 'status' => 'success', 'message' => $message, 'token' => $token);

                $response = json_encode($data);
            }
            return $response;

        } else {
            $message = "Kάτι πήγε στραβα. Προσπαθήστε ξανά!";
            $data = array('status' => 'error', 'data' => null, 'message' => $message, 401);
            $response = json_encode($data);
            return $response;
        }
    } else {

        $message = "Kάτι πήγε στραβα. Προσπαθήστε ξανά!";
        $data = array('status' => 'error', 'data' => null, 'message' => $message, 401);
        $response = json_encode($data);
        return $response;

    }

    $result->closeCursor();
    $pdo = null;
});
$app->post('/api/mobilelogin', function (Request $request, Response $response, array $args) {
    global $pdo;

    $userData = json_decode(file_get_contents('php://input'));
    $username = $userData->{'username'};
    $password = $userData->{'password'};
    // $status = 0;

    $query = "SELECT * FROM volunteer WHERE username=:username";
    $result = $pdo->prepare($query);
    $result->execute(array(':username' => $username));
    $count = $result->rowCount();
    $user = $result->fetch(PDO::FETCH_BOTH);

    if ($count == 1 && !empty($user)) {

        if ($password == $user[password]) {
            $_SESSION['username'] = $username;
            $_SESSION['success'] = "You are now logged in";
            $message = "successfully logged in";
            if (isset($_SESSION['username'])) {
                $settings = $this->get('settings');
                $token = JWT::encode(['id' => $user->id, 'username' => $user->username], $settings['jwt']['secret'], "HS256");
                $data = array("username" => $username, 'status' => 'success', 'message' => $message, 'token' => $token);

                $response = json_encode($data);
            }
            return $response;

        } else {
            $message = "Kάτι πήγε στραβα. Προσπαθήστε ξανά,strava!";
            $data = array('status' => 'error', 'data' => null, 'message' => $message, 401);
            $response = json_encode($data);
            return $response;
        }
    } else {

        $message = "Kάτι πήγε στραβα. Προσπαθήστε ξανά!";
        $data = array('status' => 'error', 'data' => null, 'message' => $message, 401);
        $response = json_encode($data);
        return $response;

    }

    $result->closeCursor();
    $pdo = null;
});

// $app->post('/api/login', function (Request $request, Response $response, array $args) {

//     $input = $request->getParsedBody();
//     $sql = "SELECT * FROM volunteer WHERE username= :username";
//     $sth = $this->db->prepare($sql);
//     $sth->bindParam("username", $input['username']);
//     $sth->execute();
//     $user = $sth->fetchObject();

//     // verify username
//     if(!$volunteer) {
//         return $this->response->withJson(['error' => true, 'message' => 'These credentials do not match our records.']);
//     }

//     // verify password.
//     if (!password_verify($input['password'],$volunteer->password)) {
//         return $this->response->withJson(['error' => true, 'message' => 'These credentials do not match our records.']);
//     }

//     $settings = $this->get('settings'); // get settings array.

//     $token = JWT::encode(['id' => $volunteer->id, 'username' => $volunteer->username], $settings['jwt']['secret'], "HS256");

//     return $this->response->withJson(['token' => $token]);

// });

$app->get('/api/volunteers', function (Request $request, Response $response, array $args) {
    global $pdo;

    //require_once ('configuration.php');

    $query = "SELECT * FROM volunteer";
    $result = $pdo->query($query);
    $data = array();
    while ($r = $result->fetch(PDO::FETCH_ASSOC)) {
        $data[] = $r;
    }
    // $object = (object) $data;
    //  print json_encode($data);

    $response = new stdClass();
    $response->data = $data;
    return json_encode($response, JSON_NUMERIC_CHECK);
});

$app->get('/api/event', function (Request $request, Response $response, array $args) {
    global $pdo;

    //require_once ('configuration.php');

    $query = "SELECT * FROM peristatiko";
    $result = $pdo->query($query);
    $data = array();
    while ($r = $result->fetch(PDO::FETCH_ASSOC)) {
        $data[] = $r;
    }
    //  print json_encode($data);
    $response = new stdClass();
    $response->data = $data;
    return json_encode($response, JSON_NUMERIC_CHECK);

});

$app->get('/api/defibrillators', function (Request $request, Response $response, array $args) {
    global $pdo;

    //require_once ('configuration.php');

    $query = "SELECT * FROM apinidotis";
    $result = $pdo->query($query);
    $data = array();
    while ($r = $result->fetch(PDO::FETCH_ASSOC)) {
        $data[] = $r;
    }

    $response = new stdClass();
    $response->data = $data;
    return json_encode($response, JSON_NUMERIC_CHECK);
});

$app->get('/api/patients', function (Request $request, Response $response, array $args) {
    global $pdo;

    //require_once ('configuration.php');

    $query = "SELECT * FROM asthenis";
    $result = $pdo->query($query);
    $data = array();
    while ($r = $result->fetch(PDO::FETCH_ASSOC)) {
        $data[] = $r;
    }
    $response = new stdClass();
    $response->data = $data;
    return json_encode($response, JSON_NUMERIC_CHECK);

});

$app->get('/api/admin', function (Request $request, Response $response, array $args) {
    global $pdo;

    //require_once ('configuration.php');

    $query = "SELECT * FROM ekab";
    $result = $pdo->query($query);
    $data = array();
    while ($r = $result->fetch(PDO::FETCH_ASSOC)) {
        $data[] = $r;
    }
    $response = new stdClass();
    $response->data = $data;
    return json_encode($response, JSON_NUMERIC_CHECK);
});

$app->post('/api/logout', function (Request $request, Response $response, array $args) {
    global $pdo;

    unset($SESSION['username']);
    session_destroy();
    $result->closeCursor();
    $pdo = null;
});

$app->get('/api/volunteers/{id}', function (Request $request, Response $response, array $args) {
    global $pdo;

    $volunteers_id = (int) $args['id'];
    $query = "SELECT * FROM volunteer WHERE id=:id";
    $result = $pdo->prepare($query);
    $result->execute(array("id" => $volunteers_id));
    while ($r = $result->fetch(PDO::FETCH_ASSOC)) {
        $data = $r;

    }
    $response = json_encode($data, JSON_NUMERIC_CHECK);
    return $response;

    $result->closeCursor();
    $pdo = null;
});

$app->post('/api/editvolunteer/{id}', function (Request $request, Response $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    $userData = json_decode(file_get_contents('php://input'));
    $volunteers_id = $args['id'];
    $username = $userData->{'username'};
    $name = $userData->{'name'};
    $surname = $userData->{'surname'};
    $password = $userData->{'password'};
    $tel1 = $userData->{'tel1'};
    $tel2 = $userData->{'tel2'};
    $RFID = $userData->{'RFID'};
    if ($tel2== 0) {$tel2 = null;};
    $email = $userData->{'email'};
      $dateofbirth = $userData->{'dateofbirth'};
  
    $latesttraining = $userData->{'latesttraining'};
    if ($latesttraining== "0000-00-00") { $latesttraining = null;};
    $address = $userData->{'address'};
    $location = $userData->{'location'};

    if (!$usernameValidator->validate($username)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Όνομα Χρήστη.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$nameValidator->validate($name)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Όνομα.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$surnameValidator->validate($surname)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Επώνυμο.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$emailValidator->validate($email)) {
        $message = "Μη αποδεκτή μορφή E-mail.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$passwordValidator->validate($password)) {
        $message = "Ο κωδικός πρέπει να είναι 10 ψηφία. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$mobileNumberValidator->validate($tel1)) {
        $message = "Mη αποδεκτή μορφή αριθμού κινητού τηλεφώνου. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$mobile2NumberValidator->validate($tel2)) {
        $message = "Mη αποδεκτή μορφή αριθμού κινητού τηλεφώνου. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$dateValidator->validate($dateofbirth)) {
        $message = "Οι ημερομηνίες πρέπει να είναι της μορφής 'ΕΕΕΕ-ΜΜ-ΗΗ'.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$trainingDateValidator->validate($latesttraining)) {
        $message = "Οι ημερομηνίες πρέπει να είναι της μορφής 'ΕΕΕΕ-ΜΜ-ΗΗ'! ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$addressValidator->validate($address)) {
        $message = "Mη αποδεκτή μορφή Διεύθυνσης. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$locationValidator->validate($location)) {
        $message = "Mη αποδεκτή μορφή Περιφέρειας. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$RFIDValidator->validate($RFID)) {
        $message = "To RFID πρέπει να είναι 16ψήφιος αριθμός. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }

    $query = "SELECT * FROM volunteer WHERE username=:username  AND id<>:id";
    $result = $pdo->prepare($query);
    $result->execute(array(':username' => $username,'id' => $volunteers_id));
    $count = $result->rowCount();
    $user = $result->fetch(PDO::FETCH_BOTH);

    if ($count == 1 && !empty($user)) {
        $message = "Υπάρχει ήδη εθελοντής με αυτο το Όνομα Χρήστη";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    } else {
        $query = "SELECT * FROM volunteer WHERE email=:email AND id<>:id";
        $result = $pdo->prepare($query);
        $result->execute(array(':email' => $email,'id' => $volunteers_id));
        $count = $result->rowCount();
        $user = $result->fetch(PDO::FETCH_BOTH);
        if ($count == 1 && !empty($user)) {
            $message = "Υπάρχει ήδη εθελοντής με αυτο το E-mail";
            $httpstatus = "error";
            $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message, 409);
            $myObj = new stdClass();
            $myObj->message = $message;
            $myObj->httpstatus = $httpstatus;
            $response = $response->withJson($myObj, 409);

            return $response;
        } else {
            $query = "UPDATE volunteer SET username=:username, name=:name,  surname=:surname, password=:password, tel1=:tel1, tel2=:tel2, email=:email, dateofbirth=:dateofbirth, latesttraining=:latesttraining, address=:address,location=:location,RFID=:RFID  WHERE id=:id";
            $result = $pdo->prepare($query);
            $result->execute(array(':username' => $username, ':name' => $name, ':surname' => $surname, ':password' => $password, ':tel1' => $tel1, ':tel2' => $tel, ':email' => $email, ':dateofbirth' => $dateofbirth, ':latesttraining' => $latesttraining, ':address' => $address, ':location' => $location, ':RFID'=>$RFID,':id' => $volunteers_id));
            $message = "success";
            
            $myObj = new stdClass();
            $myObj->id = $volunteers_id;
            $myObj->RFID = $RFID;
            $myObj->username = $username;
            $myObj->name = $name;
            $myObj->surname = $surname;
            $myObj->password = $password;
            $myObj->email = $email;
            $myObj->tel1 = $tel1;
            $myObj->tel2 = $tel2;
            $myObj->dateofbirth = $dateofbirth;
            $myObj->latesttraining = $latesttraining;
            $myObj->location = $location;
            $myObj->address = $address;
            $myObj->message = $message;

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;
        }
    }

});

$app->post('/api/deactivate/{id}', function (Request $request, Response $response, array $args) {
    global $pdo;
    $userData = json_decode(file_get_contents('php://input'));
    $volunteers_id = $args['id'];
    $status = $userData->{'status'};

    if ($status == 0) {
        $response_status = 1;

    } else {
        $response_status = 0;
    }

    $query = ("UPDATE volunteer SET status=:status WHERE id=:id");
    $result = $pdo->prepare($query);

    $result->execute(array(':status' => $response_status, ':id' => $volunteers_id));

    $myObj = new stdClass();
    $myObj->id = $volunteers_id;
    $myObj->status = $response_status;

    $response = json_encode($myObj, JSON_NUMERIC_CHECK);

    return $response;
});

$app->post('/api/defibrillator/presentflag', function (Request $request, Response $response, array $args) {
    global $pdo;
    $defibrillatorData = json_decode(file_get_contents('php://input'));
    $defibrillator_id = $defibrillatorData->{'id'};
    $flag = $defibrillatorData->{'presentflag'};
     
    if ($flag == 0) {
        $response_flag = 1;

    } else {
        $response_flag = 0;
    }

    $query = ("UPDATE apinidotis SET presentflag=:presentflag WHERE id=:id");
    $result = $pdo->prepare($query);

    $result->execute(array(':presentflag' => $response_flag, ':id' => $defibrillator_id));

    $myObj = new stdClass();
    $myObj->id = $defibrillator_id;
    $myObj->presentflag = $response_flag;

    $response = json_encode($myObj, JSON_NUMERIC_CHECK);

    return $response;
});

$app->post('/api/defibrillator/locker', function (Request $request, Response $response, array $args) {
    global $pdo;
    $defibrillatorData = json_decode(file_get_contents('php://input'));
    $defibrillator_id = $defibrillatorData->{'id'};
    $locker = $defibrillatorData->{'locker'};
     
    if ($locker == 0 ) {
        $response_locker = 1;

    } else {
        $response_locker = 0;
    }

    $query = ("UPDATE apinidotis SET locker=:locker WHERE id=:id");
    $result = $pdo->prepare($query);

    $result->execute(array(':locker' => $response_locker, ':id' => $defibrillator_id));

    $myObj = new stdClass();
    $myObj->id = $defibrillator_id;
    $myObj->locker = $response_locker;

    $response = json_encode($myObj, JSON_NUMERIC_CHECK);

    return $response;
});

$app->post('/api/insertvolunteer', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    $userData = json_decode(file_get_contents('php://input'));

    $username = $userData->{'username'};
    $name = $userData->{'name'};
    $surname = $userData->{'surname'};
    $password = $userData->{'password'};
    $tel1 = $userData->{'tel1'};
    $tel2 = $userData->{'tel2'};
    $tel2 = $userData->{'tel2'};
    $RFID = $userData->{'RFID'};
   
    $dateofbirth = $userData->{'dateofbirth'};
    if ($tel2== 0) {$tel2 = null;};
    $email = $userData->{'email'};

    $latesttraining = $userData->{'latesttraining'};
    if ($latesttraining== "0000-00-00") { $latesttraining = null;};
    $address = $userData->{'address'};
    $location = $userData->{'location'};
    $status = $userData->{'status'};

    if (!$usernameValidator->validate($username)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Όνομα Χρήστη.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$nameValidator->validate($name)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Όνομα.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$surnameValidator->validate($surname)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Επώνυμο.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$emailValidator->validate($email)) {
        $message = "Μη αποδεκτή μορφή E-mail.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$passwordValidator->validate($password)) {
        $message = "Ο κωδικός πρέπει να είναι 10 ψηφία. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$mobileNumberValidator->validate($tel1)) {
        $message = "Mη αποδεκτή μορφή αριθμού κινητού τηλεφώνου. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$mobile2NumberValidator->validate($tel2)) {
        $message = "Mη αποδεκτή μορφή αριθμού κινητού τηλεφώνου. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$dateValidator->validate($dateofbirth)) {
        $message = "Οι ημερομηνίες πρέπει να είναι της μορφής 'ΕΕΕΕ-ΜΜ-ΗΗ'.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$trainingDateValidator->validate($latesttraining)) {
        $message = "Οι ημερομηνίες πρέπει να είναι της μορφής 'ΕΕΕΕ-ΜΜ-ΗΗ'. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$addressValidator->validate($address)) {
        $message = "Mη αποδεκτή μορφή Διεύθυνσης. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$locationValidator->validate($location)) {
        $message = "Mη αποδεκτή μορφή Περιφέρειας. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$RFIDValidator->validate($RFID)) {
        $message = "To RFID πρέπει να είναι 16ψήφιος αριθμός. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }

    $query = "SELECT * FROM volunteer WHERE username=:username";
    $result = $pdo->prepare($query);
    $result->execute(array(':username' => $username));
    $count = $result->rowCount();
    $user = $result->fetch(PDO::FETCH_BOTH);

    if ($count == 1 && !empty($user)) {
        $message = "Υπάρχει ήδη εθελοντής με αυτο το Όνομα Χρήστη";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    } else {
        $query = "SELECT * FROM volunteer WHERE email=:email";
        $result = $pdo->prepare($query);
        $result->execute(array(':email' => $email));
        $count = $result->rowCount();
        $user = $result->fetch(PDO::FETCH_BOTH);
        if ($count == 1 && !empty($user)) {
            $message = "Υπάρχει ήδη εθελοντής με αυτο το E-mail";
            $httpstatus = "error";
            $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message, 409);
            $myObj = new stdClass();
            $myObj->message = $message;
            $myObj->httpstatus = $httpstatus;
            $response = $response->withJson($myObj, 409);

            return $response;
        } else {
            $status = "0";
            $query = "INSERT INTO volunteer (username,name,surname,password,tel1,tel2,email,dateofbirth,latesttraining,address,location,status,RFID) VALUES (:username,:name,:surname,:password,:tel1,:tel2,:email,:dateofbirth,:latesttraining,:address,:location,:status,:RFID)";
            $result = $pdo->prepare($query);

            $result->execute(array(':username' => $username, ':name' => $name, ':surname' => $surname, ':password' => $password, ':tel1' => $tel1, ':tel2' => $tel, ':email' => $email, ':dateofbirth' => $dateofbirth, ':latesttraining' => $latesttraining, ':address' => $address, ':location' => $location, ':status' => $status,':RFID'=>$RFID));
            $lastId = $pdo->lastInsertId();
          
            $message = "success";
            //  $response=json_encode($lastId);
            $myObj = new stdClass();
            $myObj->id = $lastId;
            $myObj->username = $username;
            $myObj->name = $name;
            $myObj->surname = $surname;
            $myObj->password = $password;
            $myObj->email = $email;
            $myObj->tel1 = $tel1;
            $myObj->tel2 = $tel2;
            $myObj->dateofbirth = $dateofbirth;
            $myObj->latesttraining = $latesttraining;
            $myObj->address = $address;
            $myObj->location = $location;
            $myObj->status = $status;
            $myObj->RFID = $RFID;
            $myObj->message = $message;
           

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;

        }
    }

});
$app->post('/api/insertevent', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    $userData = json_decode(file_get_contents('php://input'));





    $longitude = $userData->{'longitude'};
    $latitude = $userData->{'latitude'};
    $address = $userData->{'address'};
    $active=0;
    if ($longitude== null ){
        $message = "Kάτι πήγε στραβά!";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message, 409);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 404);
       

        return $response;

    }
   
   

    $query = "INSERT INTO peristatiko (longitude, latitude, address ,active) VALUES (:longitude,:latitude, :address,:active)";
   
    $result = $pdo->prepare($query);

    $result->execute(array(':longitude' => $longitude, ':latitude' => $latitude, ':address' => $address,':active'=> $active));
    $count = $result->rowCount();
    $lastId = $pdo->lastInsertId();
    $timezone  = +2;
    // $datetime = date('Y-d-m H:i:s', time()+ 3600*($timezone+date("I")));

  
$message="Επιτυχης Προσθήκη Περιστατικού";
        $myObj = new stdClass();
        $myObj->id = $lastId;
        $myObj->message = $message;
        $myObj->longitude = $longitude;
        $myObj->latitude = $latitude;
        $myObj->address = $address;
        $myObj->active = $active;
    $response=json_encode($myObj,JSON_NUMERIC_CHECK);
    return $response;
    
       
       


});
$app->post('/api/eventCorrespodence', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
 
  $userData = json_decode(file_get_contents('php://input'));
$id = $userData->{'id'};

    $query = "UPDATE peristatiko SET correspondence=:correspondence,correspondencetime=now() WHERE id=:id";
   
    $result = $pdo->prepare($query);

    $result->execute(array(':correspondence' => $correspondence,':id'=> $id));
    $query="SELECT * 
    FROM peristatiko
    ORDER BY id DESC
    LIMIT 1";
       $result = $pdo->prepare($query);
       $result->execute(array());
    $event = $result->fetch(PDO::FETCH_ASSOC);

  
 
    $response=json_encode($event,JSON_NUMERIC_CHECK);
    return $response;


});
$app->post('/api/sendEvent', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    $userData = json_decode(file_get_contents('php://input'));





    $longitude = $userData->{'longitude'};
    $latitude = $userData->{'latitude'};
    $address = $userData->{'address'};
   
 
    $query = "SELECT username FROM volunteer WHERE isOnline=:isOnline ";
    $result = $pdo->query($query);
    $result->execute(array(':isOnline' => $isOnline));
    $data = array();
    while ($r = $result->fetch(PDO::FETCH_ASSOC)) {
        $data[] = $r;
    }
    // $object = (object) $data;
    //  print json_encode($data);

    $response = new stdClass();
    $response->data = $data;
    return json_encode($response, JSON_NUMERIC_CHECK);
  
    $options = array(
      'cluster' => 'eu',
      'useTLS' => true
    );
    $pusher = new Pusher\Pusher(
      '2f7f2a748cacde676705',
      '8dff9e8bcc92dd2cd680',
      '706595',
      $options
    );
    $myObj = new stdClass();
    $myObj->longitude = $longitude;
    $myObj->latitude = $latitude;
    $myObj->address = $address;

    $data = $myObj;
    //$data['address'] = $myObj;
    $pusher->trigger('channel', 'peristatiko', $data);


    

    $interestDetails = ['unique identifier', 'ExponentPushToken[CZ5D9yFnlEr-BEoEpw9M8L]'];
  
    // You can quickly bootup an expo instance
    $expo = \ExponentPhpSDK\Expo::normalSetup();
    
    // Subscribe the recipient to the server
    $expo->subscribe($interestDetails[0], $interestDetails[1]);
    
    // Build the notification data
    $notification = ['title' => 'Υπάρχει νεο περιστατικό','body'=>$address];
    
    // Notify an interest with a notification
    
   
    $expo->notify($interestDetails[0], $notification);
       


});
$app->post('/mobile/unlockDefibrillator', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    $nearestDefibrillator = json_decode(file_get_contents('php://input'));





    $id = $nearestDefibrillator->{'id'};

   
 
  
    $options = array(
      'cluster' => 'eu',
      'useTLS' => true
    );
    $pusher = new Pusher\Pusher(
      '2f7f2a748cacde676705',
      '8dff9e8bcc92dd2cd680',
      '706595',
      $options
    );
    $myObj = new stdClass();
    $myObj->id = $id;
  

    $data = $myObj;
    //$data['address'] = $myObj;
    $pusher->trigger('channel', 'apinidotis', $data);


    

    


});


$app->get('/api/volunteer/search', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;

 $input = $request->getQueryParam('input');
  

    $query = " SELECT * FROM volunteer WHERE  username LIKE :searchedinput   OR name LIKE :searchedinput  OR email LIKE :searchedinput OR surname LIKE :searchedinput OR location LIKE :searchedinput ";
   
    $result = $pdo->prepare($query);
    $result->execute(array(':searchedinput' => "%$input%"));
   // $result->execute(array(':searchedinput' => "$input%"));
    $count = $result->rowCount();
   
    if ($count== 0){
        $message = "O χρήστης που αναζητήσατε, δεν υπάρχει!";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message, 409);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 404);
       

        return $response;

    }
    while ($r = $result->fetch(PDO::FETCH_ASSOC)) {
        $data[] = $r;
    }

    // $myObj = new stdClass();
    // $myObj->user = $user;
   
    $response = json_encode($data, JSON_NUMERIC_CHECK);

    return $response;
});
$app->get('/api/admin/search', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;

 $input = $request->getQueryParam('input');
  

    $query = " SELECT * FROM ekab WHERE  username LIKE :searchedinput   OR name LIKE :searchedinput  OR email LIKE :searchedinput OR surname LIKE :searchedinput OR address LIKE :searchedinput ";
   
    $result = $pdo->prepare($query);
    $result->execute(array(':searchedinput' => "%$input%"));
   // $result->execute(array(':searchedinput' => "$input%"));
    $count = $result->rowCount();
   
    if ($count== 0){
        $message = "O χρήστης που αναζητήσατε, δεν υπάρχει!";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message, 409);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 404);
       

        return $response;

    }
    while ($r = $result->fetch(PDO::FETCH_ASSOC)) {
        $data[] = $r;
    }

    // $myObj = new stdClass();
    // $myObj->user = $user;
   
    $response = json_encode($data, JSON_NUMERIC_CHECK);

    return $response;
});

$app->post('/api/editdefibrillator', function (Request $request, Response $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    $defibrillatorData = json_decode(file_get_contents('php://input'));
    $id = $defibrillatorData->{'id'};
    $installationdate = $defibrillatorData->{'installationdate'};
    $upgradedate = $defibrillatorData->{'upgradedate'};
    $notes = $defibrillatorData->{'notes'};
    $model = $defibrillatorData->{'model'};
    $location = $defibrillatorData->{'location'};
    $latitude = $defibrillatorData->{'latitude'};
    $longitude = $defibrillatorData->{'longitude'};


    if ($longitude== null ){
        $defmessage = "Kατι πήγε στραβά!";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'defmessage' => $defmessage, 409);
        $myObj = new stdClass();
        $myObj->defmessage = $defmessage;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 404);
       

        return $response;

    }
  
  
    if (!$defibrillatordateValidator->validate($installationdate)) {
        $defmessage = "Οι ημερομηνίες πρέπει να είναι απο 01-01-2019 εώς σήμερα.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'defmessage' => $defmessage);
        $myObj = new stdClass();
        $myObj->defmessage = $defmessage;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$defibrillatordateValidator->validate($upgradedate)) {
        $defmessage = "Οι ημερομηνίες πρέπει να είναι απο 01-01-2019 εώς σήμερα! ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'defmessage' => $defmessage);
        $myObj = new stdClass();
        $myObj->defmessage = $defmessage;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
   
  

            $query = "UPDATE apinidotis SET installationdate=:installationdate, upgradedate=:upgradedate, notes=:notes,model=:model,location=:location,latitude=:latitude,longitude=:longitude WHERE id=:id";
            $result = $pdo->prepare($query);
            $result->execute(array(':installationdate' => $installationdate,  ':upgradedate' => $upgradedate, ':notes' => $notes, ':model' => $model,':location' => $location,':latitude' => $latitude,':longitude' => $longitude,  ':id' => $id));
            $message = "success";
            
            $myObj = new stdClass();
            $myObj->id = $id;
            $myObj->installationdate = $installationdate;
   
            $myObj->upgradedate = $upgradedate;
            $myObj->notes = $notes;
            $myObj->message = $message;
            $myObj->model = $model;
            $myObj->location = $location;
            $myObj->latitude = $latitude;
            $myObj->longitude = $longitude;
         

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;
     

});

$app->post('/api/insertpatient', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    $patientData = json_decode(file_get_contents('php://input'));

    $name = $patientData->{'name'};
  
    $surname = $patientData->{'surname'};
    $address = $patientData->{'address'};
    $history = $patientData->{'history'};
    $gender = $patientData->{'gender'};

   
    $description = $patientData->{'description'};

    $birthdate = $patientData->{'birthdate'};
 
    if (!$addressValidator->validate($address)) {
        $patmessage = "Mη αποδεκτή μορφή Διεύθυνσης. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'patmessage' => $patmessage);
        $myObj = new stdClass();
        $myObj->patmessage = $patmessage;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }

    if (!$nameValidator->validate($name)) {
        $patmessage = "Πληκτρολογήσατε μη αποδεκτό Όνομα.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'patmessage' => $patmessage);
        $myObj = new stdClass();
        $myObj->patmessage = $patmessage;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$surnameValidator->validate($surname)) {
        $patmessage = "Πληκτρολογήσατε μη αποδεκτό Επώνυμο.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'patmessage' => $patmessage);
        $myObj = new stdClass();
        $myObj->patmessage = $patmessage;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$patientDateOfBirth->validate($birthdate)) {
        $patmessage = "To έτος γέννησης πρέπει να είναι απο το 1950 εως 2010";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'patmessage' => $patmessage);
        $myObj = new stdClass();
        $myObj->patmessage = $patmessage;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
          

    
   
            $query = "INSERT INTO asthenis (name,surname,address,history,description,birthdate,gender) VALUES (:name,:surname,:address,:history,:description,:birthdate,:gender)";
            $result = $pdo->prepare($query);

            $result->execute(array( ':name' => $name, ':surname' => $surname, ':address' => $address, ':history' => $history, ':description' => $description, ':birthdate' => $birthdate, ':gender' => $gender));
            $lastId = $pdo->lastInsertId();
          
            $message = "success";
            //  $response=json_encode($lastId);
            $myObj = new stdClass();
            $myObj->id = $lastId;
        
            $myObj->name = $name;
            $myObj->surname = $surname;
            $myObj->address = $address;
            $myObj->history = $history;
            $myObj->description = $description;
            $myObj->birthdate = $birthdate;
            $myObj->gender = $gender;
         
            
            $myObj->message = $message;
           

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;

     

});
$app->post('/api/editpatient/{id}', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    $patientData = json_decode(file_get_contents('php://input'));
    $patient_id = $args['id'];
    $name = $patientData->{'name'};
  
    $surname = $patientData->{'surname'};
    $address = $patientData->{'address'};
    $history = $patientData->{'history'};
    $gender = $patientData->{'gender'};

   
    $description = $patientData->{'description'};

    $birthdate = $patientData->{'birthdate'};
 
    if (!$addressValidator->validate($address)) {
        $patmessage = "Mη αποδεκτή μορφή Διεύθυνσης. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'patmessage' => $patmessage);
        $myObj = new stdClass();
        $myObj->patmessage = $patmessage;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }

    if (!$nameValidator->validate($name)) {
        $patmessage = "Πληκτρολογήσατε μη αποδεκτό Όνομα.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'patmessage' => $patmessage);
        $myObj = new stdClass();
        $myObj->patmessage = $patmessage;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$surnameValidator->validate($surname)) {
        $patmessage = "Πληκτρολογήσατε μη αποδεκτό Επώνυμο.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'patmessage' => $patmessage);
        $myObj = new stdClass();
        $myObj->patmessage = $patmessage;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$patientDateOfBirth->validate($birthdate)) {
        $patmessage = "To έτος γέννησης πρέπει να είναι απο το 1950 εως 2010";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'patmessage' => $patmessage);
        $myObj = new stdClass();
        $myObj->patmessage = $patmessage;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }

        $query = "UPDATE asthenis SET name=:name,  surname=:surname, address=:address, history=:history, gender=:gender, description=:description, birthdate=:birthdate WHERE id=:id";
        $result = $pdo->prepare($query);

        $result->execute(array( ':name' => $name, ':surname' => $surname, ':address' => $address, ':history' => $history, ':description' => $description, ':birthdate' => $birthdate, ':gender' => $gender,':id'=>$patient_id));
        $lastId = $pdo->lastInsertId();
      
        $message = "success";
        //  $response=json_encode($lastId);
        $myObj = new stdClass();
        $myObj->id = $patient_id;
    
        $myObj->name = $name;
        $myObj->surname = $surname;
        $myObj->address = $address;
        $myObj->history = $history;
        $myObj->description = $description;
        $myObj->birthdate = $birthdate;
        $myObj->gender = $gender;
     
        
        $myObj->message = $message;
       

        $response = json_encode($myObj, JSON_NUMERIC_CHECK);

        return $response;

 

});

$app->post('/api/insertadmin', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    $adminData = json_decode(file_get_contents('php://input'));

    $username = $adminData->{'username'};
    $name = $adminData->{'name'};
    $surname = $adminData->{'surname'};
    $password = $adminData->{'password'};
 

    $address = $adminData->{'address'};
    $email = $adminData->{'email'};
    $type = $adminData->{'type'};

    if (!$usernameValidator->validate($username)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Όνομα Χρήστη.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->admmessage = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$nameValidator->validate($name)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Όνομα.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->admmessage = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$surnameValidator->validate($surname)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Επώνυμο.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->admmessage = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$emailValidator->validate($email)) {
        $message = "Μη αποδεκτή μορφή E-mail.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->admmessage = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$adminTypeValidator->validate($type)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Tύπο διαχειριστή.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->admmessage = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
   
 
   

    if (!$addressValidator->validate($address)) {
        $message = "Mη αποδεκτή μορφή Διεύθυνσης. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->admmessage = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
  

    $query = "SELECT * FROM ekab WHERE username=:username  ";
    $result = $pdo->prepare($query);
    $result->execute(array(':username' => $username));
    $count = $result->rowCount();
    $user = $result->fetch(PDO::FETCH_BOTH);

    if ($count == 1 && !empty($user)) {
        $message = "Υπάρχει ήδη διαχειριστής με αυτο το Όνομα Χρήστη";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->admmessage = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    } else {
        $query = "SELECT * FROM ekab WHERE email=:email ";
        $result = $pdo->prepare($query);
        $result->execute(array(':email' => $email));
        $count = $result->rowCount();
        $user = $result->fetch(PDO::FETCH_BOTH);
        if ($count == 1 && !empty($user)) {
            $message = "Υπάρχει ήδη διαχειριστής με αυτο το E-mail";
            $httpstatus = "error";
            $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message, 409);
            $myObj = new stdClass();
            $myObj->admmessage = $message;
            $myObj->httpstatus = $httpstatus;
            $response = $response->withJson($myObj, 409);

            return $response;
        } else {
           
            $query = "INSERT INTO ekab (username,name,surname,password,email,address,type) VALUES (:username,:name,:surname,:password,:email,:address,:type)";
            $result = $pdo->prepare($query);

            $result->execute(array(':username' => $username, ':name' => $name, ':surname' => $surname, ':password' => $password, ':email' => $email, ':address' => $address, ':type' => $type));
            $lastId = $pdo->lastInsertId();
          
            $message = "success";
            //  $response=json_encode($lastId);
            $myObj = new stdClass();
            $myObj->id = $lastId;
            $myObj->username = $username;
            $myObj->name = $name;
            $myObj->surname = $surname;
            $myObj->password = $password;
            $myObj->email = $email;
            $myObj->type = $type;
           
    
            $myObj->address = $address;

            
            $myObj->message = $message;
           

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;

        }
    }

});
$app->post('/api/editadmin/{id}', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    
    $adminData = json_decode(file_get_contents('php://input'));
    $admin_id = $args['id'];

    $username = $adminData->{'username'};
    $name = $adminData->{'name'};
    $surname = $adminData->{'surname'};
    $password = $adminData->{'password'};
 

    $address = $adminData->{'address'};
    $email = $adminData->{'email'};
    $type = $adminData->{'type'};

    if (!$usernameValidator->validate($username)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Όνομα Χρήστη.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->admmessage = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$nameValidator->validate($name)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Όνομα.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->admmessage = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$surnameValidator->validate($surname)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Επώνυμο.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->admmessage = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$emailValidator->validate($email)) {
        $message = "Μη αποδεκτή μορφή E-mail.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->admmessage = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
    if (!$adminTypeValidator->validate($type)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Tύπο διαχειριστή.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->admmessage = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
   
 
   

    if (!$addressValidator->validate($address)) {
        $message = "Mη αποδεκτή μορφή Διεύθυνσης. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->admmessage = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
  

    $query = "SELECT * FROM ekab WHERE username=:username AND id<>:id";
    $result = $pdo->prepare($query);
    $result->execute(array(':username' => $username,':id'=>$admin_id));
    $count = $result->rowCount();
    $user = $result->fetch(PDO::FETCH_BOTH);

    if ($count == 1 && !empty($user)) {
        $message = "Υπάρχει ήδη διαχειριστής με αυτο το Όνομα Χρήστη";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->admmessage = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    } else {
        $query = "SELECT * FROM ekab WHERE email=:email AND id<>:id";
        $result = $pdo->prepare($query);
        $result->execute(array(':email' => $email,':id'=>$admin_id));
        $count = $result->rowCount();
        $user = $result->fetch(PDO::FETCH_BOTH);
        if ($count == 1 && !empty($user)) {
            $message = "Υπάρχει ήδη διαχειριστής με αυτο το E-mail";
            $httpstatus = "error";
            $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message, 409);
            $myObj = new stdClass();
            $myObj->admmessage = $message;
            $myObj->httpstatus = $httpstatus;
            $response = $response->withJson($myObj, 409);

            return $response;
        } else {
           
            $query = "UPDATE ekab SET username=:username, name=:name, surname=:surname,password=:password,email=:email,address=:address,type=:type WHERE id=:id";
            $result = $pdo->prepare($query);

            $result->execute(array(':username' => $username, ':name' => $name, ':surname' => $surname, ':password' => $password, ':email' => $email, ':address' => $address, ':type' => $type,':id'=>$admin_id));
            $lastId = $pdo->lastInsertId();
          
            $message = "success";
            //  $response=json_encode($lastId);
            $myObj = new stdClass();
            $myObj->id = $admin_id;
            $myObj->username = $username;
            $myObj->name = $name;
            $myObj->surname = $surname;
            $myObj->password = $password;
            $myObj->email = $email;
            $myObj->type = $type;
          
    
            $myObj->address = $address;

            
            $myObj->message = $message;
           

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;

        }
    }

});

$app->post('/api/mobile/changepassword', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    
    $userData = json_decode(file_get_contents('php://input'));
    $volunteer_id = $userData->{'id'};

    $password = $userData->{'password'};
    if (!$passwordValidator->validate($password)) {
        $message = "Ο κωδικός πρέπει να είναι 10 ψηφία. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
 

 
 
           
            $query = "UPDATE volunteer SET password=:password WHERE id=:id";
            $result = $pdo->prepare($query);

            $result->execute(array(':password' => $password,':id'=>$volunteer_id));
         
          
            $message = "success";
            //  $response=json_encode($lastId);
            $myObj = new stdClass();
            $myObj->id = $volunteer_id;
   
            $myObj->password = $password;
       
            
            $myObj->message = $message;
           

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;


});
$app->post('/api/mobile/changeaddress', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    
    $userData = json_decode(file_get_contents('php://input'));
    $volunteer_id = $userData->{'id'};

    $address = $userData->{'address'};
    if (!$addressValidator->validate($address)) {
        $message = "Mη αποδεκτή μορφή Διεύθυνσης. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
 

 
 
           
            $query = "UPDATE volunteer SET address=:address WHERE id=:id";
            $result = $pdo->prepare($query);

            $result->execute(array(':address' => $address,':id'=>$volunteer_id));
         
          
            $message = "success";
            //  $response=json_encode($lastId);
            $myObj = new stdClass();
            $myObj->id = $volunteer_id;
   
            $myObj->address = $address;
       
            
            $myObj->message = $message;
           

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;


});
$app->post('/api/mobile/changelocation', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    
    $userData = json_decode(file_get_contents('php://input'));
    $volunteer_id = $userData->{'id'};

    $location = $userData->{'location'};
    if (!$locationValidator->validate($location)) {
        $message = "Mη αποδεκτή μορφή Περιφέρειας. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
 

 
 
           
            $query = "UPDATE volunteer SET location=:location WHERE id=:id";
            $result = $pdo->prepare($query);

            $result->execute(array(':location' => $location,':id'=>$volunteer_id));
         
          
            $message = "success";
            //  $response=json_encode($lastId);
            $myObj = new stdClass();
            $myObj->id = $volunteer_id;
   
            $myObj->location = $location;
       
            
            $myObj->message = $message;
           

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;


});
$app->post('/api/mobile/changename', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    
    $userData = json_decode(file_get_contents('php://input'));
    $volunteer_id = $userData->{'id'};

    $name = $userData->{'name'};
    if (!$nameValidator->validate($name)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Όνομα Χρήστη.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
 

 
 
           
            $query = "UPDATE volunteer SET name=:name WHERE id=:id";
            $result = $pdo->prepare($query);

            $result->execute(array(':name' => $name,':id'=>$volunteer_id));
         
          
            $message = "success";
            //  $response=json_encode($lastId);
            $myObj = new stdClass();
            $myObj->id = $volunteer_id;
   
            $myObj->name = $name;
       
            
            $myObj->message = $message;
           

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;


});
$app->post('/api/mobile/changesurname', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    
    $userData = json_decode(file_get_contents('php://input'));
    $volunteer_id = $userData->{'id'};

    $surname = $userData->{'surname'};
    if (!$surnameValidator->validate($surname)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Επώνυμο.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
 

 
 
           
            $query = "UPDATE volunteer SET surname=:surname WHERE id=:id";
            $result = $pdo->prepare($query);

            $result->execute(array(':surname' => $surname,':id'=>$volunteer_id));
         
          
            $message = "success";
            //  $response=json_encode($lastId);
            $myObj = new stdClass();
            $myObj->id = $volunteer_id;
   
            $myObj->surname = $surname;
       
            
            $myObj->message = $message;
           

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;


});

$app->post('/api/mobile/changetel', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    
    $userData = json_decode(file_get_contents('php://input'));
    $volunteer_id = $userData->{'id'};

    $tel1 = $userData->{'tel1'};
    if (!$mobileNumberValidator->validate($tel1)) {
        $message = "Mη αποδεκτή μορφή αριθμού κινητού τηλεφώνου. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
 

 
 
           
            $query = "UPDATE volunteer SET tel1=:tel1 WHERE id=:id";
            $result = $pdo->prepare($query);

            $result->execute(array(':tel1' => $tel1,':id'=>$volunteer_id));
         
          
            $message = "success";
            //  $response=json_encode($lastId);
            $myObj = new stdClass();
            $myObj->id = $volunteer_id;
   
            $myObj->tel1 = $tel1;
       
            
            $myObj->message = $message;
           

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;


});

$app->post('/api/mobile/changetel2', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    
    $userData = json_decode(file_get_contents('php://input'));
    $volunteer_id = $userData->{'id'};

    $tel2 = $userData->{'tel2'};
    if (!$mobile2NumberValidator->validate($tel2)) {
        $message = "Mη αποδεκτή μορφή αριθμού κινητού τηλεφώνου. ";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
 

 
 
           
            $query = "UPDATE volunteer SET tel2=:tel2 WHERE id=:id";
            $result = $pdo->prepare($query);

            $result->execute(array(':tel2' => $tel2,':id'=>$volunteer_id));
         
          
            $message = "success";
            //  $response=json_encode($lastId);
            $myObj = new stdClass();
            $myObj->id = $volunteer_id;
   
            $myObj->tel2 = $tel2;
       
            
            $myObj->message = $message;
           

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;


});
$app->post('/api/mobile/changeuseractivity', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    
    $userData = json_decode(file_get_contents('php://input'));
    $volunteer_id = $userData->{'id'};

    $isOnline = $userData->{'isOnline'};
    if ($isOnline==false){
        $isOnline = 0;
    };
    if ($isOnline==true){
        $isOnline = 1;
    };
      $query = "UPDATE volunteer SET isOnline=:isOnline WHERE id=:id";
            $result = $pdo->prepare($query);

            $result->execute(array(':isOnline' => $isOnline,':id'=>$volunteer_id));
         
          
            $message = "success";
            //  $response=json_encode($lastId);
            $myObj = new stdClass();
            $myObj->id = $volunteer_id;
   
            $myObj->isOnline = $isOnline;
       
            
            $myObj->message = $message;
           

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;


});

$app->post('/api/mobile/changeemail', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    
    $userData = json_decode(file_get_contents('php://input'));
    $volunteer_id = $userData->{'id'};

    $email = $userData->{'email'};
    $query = "SELECT * FROM volunteer WHERE email=:email AND id<>:id";
    $result = $pdo->prepare($query);
    $result->execute(array(':email' => $email,'id' => $volunteers_id));
    $count = $result->rowCount();
    $user = $result->fetch(PDO::FETCH_BOTH);
    if ($count == 1 && !empty($user)) {
        $message = "Υπάρχει ήδη εθελοντής με αυτο το E-mail";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message, 409);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    } 
    if (!$emailValidator->validate($email)) {
        $message = "Μη αποδεκτή μορφή E-mail.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
 

 
 
           
            $query = "UPDATE volunteer SET email=:email WHERE id=:id";
            $result = $pdo->prepare($query);

            $result->execute(array(':email' => $email,':id'=>$volunteer_id));
         
          
            $message = "success";
            //  $response=json_encode($lastId);
            $myObj = new stdClass();
            $myObj->id = $volunteer_id;
   
            $myObj->email = $email;
       
            
            $myObj->message = $message;
           

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;


});
$app->post('/api/mobile/changeusername', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
    require_once 'validation/validationRules.php';
    
    $userData = json_decode(file_get_contents('php://input'));
    $volunteer_id = $userData->{'id'};

    $username = $userData->{'username'};
    $query = "SELECT * FROM volunteer WHERE username=:username AND id<>:id";
    $result = $pdo->prepare($query);
    $result->execute(array(':username' => $username,'id' => $volunteers_id));
    $count = $result->rowCount();
    $user = $result->fetch(PDO::FETCH_BOTH);
    if ($count == 1 && !empty($user)) {
        $message = "Υπάρχει ήδη εθελοντής με αυτο το Όνομα Χρήστη";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message, 409);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    } 
    if (!$usernameValidator->validate($username)) {
        $message = "Πληκτρολογήσατε μη αποδεκτό Όνομα Χρήστη.";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 409);

        return $response;
    }
 

 
 
           
            $query = "UPDATE volunteer SET username=:username WHERE id=:id";
            $result = $pdo->prepare($query);

            $result->execute(array(':username' => $username,':id'=>$volunteer_id));
         
          
            $message = "success";
            //  $response=json_encode($lastId);
            $myObj = new stdClass();
            $myObj->id = $volunteer_id;
   
            $myObj->username = $username;
       
            
            $myObj->message = $message;
           

            $response = json_encode($myObj, JSON_NUMERIC_CHECK);

            return $response;


});


$app->get('/api/login/success', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;

   $input = $request->getQueryParam('input');


    $query = " SELECT * FROM ekab WHERE  username=:username ";
   

    $result = $pdo->prepare($query);
    $result->execute(array(':username' => $input));
  
   
    $count = $result->rowCount();
   
    if ($count== 0){
        $message = "O χρήστης που αναζητήσατε, δεν υπάρχει!";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message, 409);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 404);
       

        return $response;

    }
    $user = $result->fetch(PDO::FETCH_ASSOC);
  

    // $myObj = new stdClass();
    // $myObj->user = $user;
   
    $response = json_encode($user, JSON_NUMERIC_CHECK);
    return $response;

   
});
$app->get('/api/volunteerlogin/success', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;

   $input = $request->getQueryParam('input');


    $query = " SELECT * FROM volunteer WHERE  username=:username ";
   

    $result = $pdo->prepare($query);
    $result->execute(array(':username' => $input));
  
   
    $count = $result->rowCount();
   
    if ($count== 0){
        $message = "O χρήστης που αναζητήσατε, δεν υπάρχει!";
        $httpstatus = "error";
        $data = array('httpstatus' => $httpstatus, 'data' => null, 'message' => $message, 409);
        $myObj = new stdClass();
        $myObj->message = $message;
        $myObj->httpstatus = $httpstatus;
        $response = $response->withJson($myObj, 404);
       

        return $response;

    }
    $user = $result->fetch(PDO::FETCH_ASSOC);
  

    // $myObj = new stdClass();
    // $myObj->user = $user;
   
    $response = json_encode($user, JSON_NUMERIC_CHECK);
    return $response;

   
});
$app->post('/api/arduino/simulator', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
//url example = http://localhost:8080/api/arduino/simulator?input&locker=1&id=1&presentflag=1
   $locker = $request->getQueryParam('locker');
   $defibrillator_id=$request->getQueryParam('id');
   $presentflag=$request->getQueryParam('presentflag');
   $temperature=$request->getQueryParam('temperature');
   $rfid=$request->getQueryParam('rfid');
if ($locker!==null && $presentflag!==null){
   $query = "UPDATE apinidotis SET locker=:locker, presentflag=:presentflag WHERE id=:id";
   $result = $pdo->prepare($query);
   $result->execute(array(':locker' => $locker, ':presentflag' => $presentflag, ':id' => $defibrillator_id));
   print_r("prelocker");
  
}elseif($locker!==null){
    $query = "UPDATE apinidotis SET locker=:locker WHERE id=:id";
    $result = $pdo->prepare($query);
    $result->execute(array(':locker' => $locker, ':id' => $defibrillator_id));
    $identifier=("locker");
}elseif($presentflag!==null){
    $query = "UPDATE apinidotis SET presentflag=:presentflag WHERE id=:id";
    $result = $pdo->prepare($query);
    $result->execute(array( ':presentflag' => $presentflag, ':id' => $defibrillator_id));
    $identifier=("presentflag");
}elseif($temperature<30){
    $identifier=("lowtempwarning");
}elseif($temperature>50){
    $identifier=("hightempwarning");
}

$options = array(
    'cluster' => 'eu',
    'useTLS' => true
  );
  $pusher = new Pusher\Pusher(
    '2f7f2a748cacde676705',
    '8dff9e8bcc92dd2cd680',
    '706595',
    $options
  );


   $myObj = new stdClass();
   $myObj->locker = $locker;
   $myObj->id = $defibrillator_id;
   $myObj->presentflag = $presentflag;
   $myObj->identifier = $identifier;
   $myObj->rfid = $rfid;
   $data = $myObj;

   $pusher->trigger('channel', 'arduino', $data);
   
  
    return json_encode($myObj);

   
});

$app->post('/api/sendMessage', function (ServerRequestInterface $request, ResponseInterface $response, array $args) {
    global $pdo;
 
    $sendData = json_decode(file_get_contents('php://input'));
    $message = $sendData->{'message'};

    //  function sendPushNotification($to="",$data=array()){
    //      $apikey="AIzaSyCw6_PWhd1g_xsZV9GB06qxI0mlL47FWOQ";
    //      $fields = array('to'=> $to, "notification" => $data);
    //      $url='https://fcm.googleapis.com/fcm/send';

    //      $ch=curl_init();
    //      curl_setopt($ch, CURLOPT_URL, $url);
    //      curl_setopt($ch, CURLOPT_POST, true); 
    //      curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    //      curl_setopt($ch, CURLOPT_RETURNTRANSFER,true);
    //      curl_setopt($ch, CURLOPT_SSL_VERIFYPEER,false);
    //      curl_setopt($ch, CURLOPT_POSTFIELDS,json_encode($fields));
    //      $result=curl_exec($ch);
    //      curl_close($ch);
    //      return json_decode($result,true);
    //  }
    //  $to=("1:7301688649:android:dfdb3bbaaa45dc12");
    //  $data=array('title' => 'Έχετε νέο μήνυμα','body'=>$message);
    //  print_r(sendPushNotification($to,$data));
   
    $interestDetails = ['heartbit-e68af', 'ExponentPushToken[AIzaSyCOqeCk4dFAwwnjMk7fQZ8xxeogwrNdlnU]'];
  
    // You can quickly bootup an expo instance
    $expo = \ExponentPhpSDK\Expo::normalSetup();
    
    // Subscribe the recipient to the server
    $expo->subscribe($interestDetails[0], $interestDetails[1]);
    
    // Build the notification data
    $notification = ['title' => 'Έχετε νέο μήνυμα','body'=>$message];
    
    // Notify an interest with a notification
    
   
    $expo->notify($interestDetails[0], $notification);
    return json_encode($myObj);
   
    

   
});

$app->add(function ($req, $res, $next) {
    $response = $next($req, $res);
    return $response
        ->withHeader('Access-Control-Allow-Origin', '*')
        ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
});

// $app->get('/auth', function ($request, $response, $args) {

//     $response->getBody()->write(getenv("SECRET_KEY"));

//     return $response;
// })->add($Test);
