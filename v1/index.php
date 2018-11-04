<?php

require_once '../include/DbHandler.php';
require_once '../include/PassHash.php';
require '.././libs/Slim/Slim.php';

\Slim\Slim::registerAutoloader();

$app = new \Slim\Slim();

$user_online_id = null;

/**
 * Authentikál minden request-et. Ellenőrzi az authorization header-ben mega-
 * dott api_key helyességét.
 */
function authenticate(\Slim\Route $route) {
  
  $headers = apache_request_headers();
  $response = array();
  $app = \Slim\Slim::getInstance();

  if (isset($headers['authorization'])) {
    // Authorization header validálva.
    $db = new DbHandler();
    $api_key = $headers['authorization'];
    
    if (!$db->isApiKeyExists($api_key)) {
      // Az adatbázis nem tartalmazza az authorization header-ben megadott 
      // api_key-t.
      $response["error"] = true;
      $response["message"] = "Access Denied. Invalid Api key.";
      echoResponse(401, $response);
      $app->stop();
    } else {
      // Az adatbázis tartalmazza az authorization header-ben megadott 
      // api_key-t.
      global $user_online_id;
      $user_online_id = $db->getUserOnlineIdByApiKey($api_key);
    }
  } else {
    // Az authorization header nincs kitöltve, így az api_key is hiányzik.
    $response["error"] = true;
    $response["message"] = "Api key is missing.";
    echoResponse(400, $response);
    $app->stop();
  }
}

/**
 * --------------------- Authentikáció nélküli metódusok ----------------------
 */

/*
 * ------------------------ user tábla metódusai -----------------------------
 */

/**
 * Regisztrálja az adott User-t a megadott adatokkal.
 * POST metódus
 * url /register
 * @param String $user_online_id A regisztrálandó User-hez tartozó 
 * user_online_id.
 * @param String $name Description A regisztrálandó User-hez tartozó name.
 * @param String $email Description A regisztrálandó User-hez tartozó email.
 * @param String $password Description A regisztrálandó User-hez tartozó 
 * password.
 */
$app->post('/user/register', function() use ($app) {
  
  verifyRequiredJSONParams(array('user_online_id', 'name', 'email', 
      'password'));

  $json = $app->request->getBody();
  $data = json_decode($json, true);
  $user_online_id = $data["user_online_id"];
  $name = $data["name"];
  $email = $data["email"];
  $password = $data["password"];

  $db = new DbHandler();
  $res = $db->createUser($user_online_id, $name, $email, $password);
  
  $response = array();

  if ($res == USER_CREATED_SUCCESSFULLY) {
    $response["error"] = false;
    $response["message"] = "You are successfully registered.";
  } else if ($res == USER_CREATE_FAILED) {
    $response["error"] = true;
    $response["message"] = "Oops! An error occurred while registereing.";
  } else if ($res == USER_ALREADY_EXISTED) {
    $response["error"] = true;
    $response["message"] = "Sorry, this email already existed.";
  }
  
  echoResponse(201, $response);
});

/**
 * Bejelentkezteti az adott User-t a megadott adatokkal.
 * POST metódus
 * url /login
 * @param String $email A bejelentkeztetendő User-hez tartozó email.
 * @param String $password A bejelentkeztetendő User-hez tartozó password.
 */
$app->post('/user/login', function() use ($app) {
  
  verifyRequiredJSONParams(array('email', 'password'));
  
  $json = $app->request->getBody();
  $data = json_decode($json, true);
  $email = $data["email"];
  $password = $data["password"];
  $response = array();

  $db = new DbHandler();
  if ($db->checkLogin($email, $password)) {
    $user = $db->getUserByEmail($email);

    if ($user != NULL) {
      $response['error'] = false;
      $response['user_online_id'] = $user['user_online_id'];
      $response['name'] = $user['name'];
      $response['email'] = $user['email'];
      $response['api_key'] = $user['api_key'];
    } else {
      $response['error'] = true;
      $response['message'] = "An error occurred. Please try again.";
    }
  } else {
    $response['error'] = true;
    $response['message'] = 'Login failed. Incorrect credentials.';
  }

  echoResponse(200, $response);
});

$app->post('/user/reset_password', function() use($app) {

  verifyRequiredJSONParams(array('email'));
  
  $json = $app->request->getBody();
  $data = json_decode($json, true);
  $email = $data["email"];
  
  $db = new DbHandler();

  $response = $db->resetUserPassword($email);
  $password = $response["password"];
  $name = $response["name"];
  
  if ($response != null) {
    $to = $email;
    $subject = 'Password reset';
    $message = 'Dear ' . $name . ',<br>'
            . '<p>you requested a password reset. Your new password is: '
            . '<strong>' . $password . '</strong>.</p>'
            . 'Best regards,<br>'
            . 'Todo Cloud Team';
    $headers = 'From: webmaster@example.com' . "\r\n" .
      'Reply-To: webmaster@example.com' . "\r\n" .
      'X-Mailer: PHP/' . phpversion();
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=ISO-8859-1\r\n";

    mail($to, $subject, $message, $headers);
    
    $response = array();
    
    $response["error"] = false;
    $response["message"] = "Password reset successful.";
    echoResponse(200, $response);
  } else {
    $response["error"] = true;
    $response["message"] = "Failed to reset password. Please try again!";
    echoResponse(500, $response);
  }
});

/*
 * ------------------- Authentikációt tartalmazó metódusok --------------------
 */

/*
 * Send the next row version for the given table and the given user.
 */
$app->get('/get_next_row_version/:table', 'authenticate', function($table) {
  global $user_online_id;
  $response = array();
  $db = new DbHandler();

  $next_row_version = $db->getNextRowVersion($table, $user_online_id);

  if ($next_row_version != NULL) {
    $response["error"] = false;
    $response["next_row_version"] = $next_row_version;
    echoResponse(200, $response);
  } else {
    $response["error"] = false;
    $response["next_row_version"] = $next_row_version;
    $response["message"] = "Failed the get next_row_version. Please try again!";
    echoResponse(500, $response);
  }
});

/*
 * ------------------------ user tábla metódusai -----------------------------
 */

$app->post('/user/modify_password', 'authenticate', function() use($app) {

  verifyRequiredJSONParams(array('password'));

  global $user_online_id;
  $json = $app->request->getBody();
  $data = json_decode($json, true);
  $password = $data["password"];
  
  $db = new DbHandler();
  $response = array();
  
  $success = $db->modifyUserPassword($user_online_id, $password);
  
  if ($success) {
    $response["error"] = false;
    $response["message"] = "Password modified successfully.";
    echoResponse(200, $response);
  } else {
    $response["error"] = true;
    $response["message"] = "Failed failed to modify password. Please try again!";
    echoResponse(500, $response);
  }
});

/*
 * ------------------------- todo tábla metódusai ----------------------------
 */

/**
 * Az adott User-hez tartozó összes Todo lekérése row_version alapján.
 * GET metódus
 * url /todo/:row_version
 */
$app->get('/todo/:row_version', 'authenticate', function($row_version) {
  global $user_online_id;
  $response = array();
  $db = new DbHandler();

  $todos = $db->getTodos($row_version, $user_online_id);

  if ($todos != NULL) {
    $response["error"] = false;
    $response["todos"] = $todos;
    echoResponse(200, $response);
  } else {
    $response["error"] = false;
    $response["todos"] = $todos;
    $response["message"] = "Your local db is up to date.";
    echoResponse(200, $response);
  }
});

/**
 * Az adott Todo frissítése a megadott adatok alapján.
 * PUT metódus
 * url /todo/update
 * @param String $todo_online_id A frissítendő Todo-hoz tartozó todo_online_id.
 * @param String $list_online_id A frissítendő Todo-hoz tartozó új 
 * list_online_id.
 * @param String $title A frissítendő Todo-hoz tartozó új title.
 * @param Integer $prioirity A frissítendő Todo-hoz tartozó új prioirity.
 * @param Integer $due_date A frissítendő Todo-hoz tartozó új due_date.
 * @param Integer $reminder_date_time A frissítendő Todo-hoz tartozó új 
 * reminder_date_time.
 * @param String $description A frissítendő Todo-hoz tartozó új description.
 * @param Integer $completed A frissítendő Todo-hoz tartozó új completed.
 * @param Integer $deleted A frissítendő Todo-hoz tartozó új deleted.
 */
// 000webhost.com don't allow PUT and DELETE requests for free accounts
//$app->put('/todo/update', 'authenticate', function() use($app) {
$app->post('/todo/update', 'authenticate', function() use($app) {

  verifyRequiredJSONParams(array('todo_online_id', 'title', 'priority', 
      'due_date', 'completed', 'row_version', 'deleted', 'position'));

  global $user_online_id;
  $json = $app->request->getBody();
  $data = json_decode($json, true);
  $todo_online_id = $data["todo_online_id"];
  if ($data["list_online_id"] != null) {
    $list_online_id = $data["list_online_id"];
  } else {
    $list_online_id = null;
  }
  $title = $data["title"];
  $priority = $data["priority"];
  if ($data["due_date"] != null || $data["due_date"] != 0) {
    $due_date = $data["due_date"];
  } else {
    $due_date = null;
  }
  if ($data["reminder_date_time"] != null || $data["reminder_date_time"] != 0) {
    $reminder_date_time = $data["reminder_date_time"];
  } else {
    $reminder_date_time = null;
  }
  if ($data["description"] != null) {
    $description = $data["description"];
  } else {
    $description = null;
  }
  $completed = $data["completed"];
  $row_version = $data["row_version"];
  $deleted = $data["deleted"];
  $position = $data["position"];

  $db = new DbHandler();
  $response = array();
  
  $success = $db->updateTodo($todo_online_id, $user_online_id, 
          $list_online_id, $title, $priority, $due_date, $reminder_date_time, 
          $description, $completed, $row_version, $deleted, $position);
  
  if ($success) {
    $response["error"] = false;
    $response["message"] = "Todo updated successfully.";
    echoResponse(200, $response);
  } else {
    $response["error"] = true;
    $response["message"] = "Todo failed to update. Please try again!";
    echoResponse(500, $response);
  }
});

/**
 * Az adott Todo létrehozása a megadott adatokkal.
 * POST metódus
 * url /todo/insert
 * @param String $todo_online_id A frissítendő Todo-hoz tartozó todo_online_id.
 * @param String $list_online_id A frissítendő Todo-hoz tartozó új 
 * list_online_id.
 * @param String $title A frissítendő Todo-hoz tartozó új title.
 * @param Integer $prioirity A frissítendő Todo-hoz tartozó új prioirity.
 * @param Integer $due_date A frissítendő Todo-hoz tartozó új due_date.
 * @param Integer $reminder_date_time A frissítendő Todo-hoz tartozó új 
 * reminder_date_time.
 * @param String $description A frissítendő Todo-hoz tartozó új description.
 * @param Integer $completed A frissítendő Todo-hoz tartozó új completed.
 * @param Integer $deleted A frissítendő Todo-hoz tartozó új deleted.
 */
$app->post('/todo/insert', 'authenticate', function() use ($app) {
  
  verifyRequiredJSONParams(array('todo_online_id', 'title', 'priority', 
      'due_date', 'completed', 'row_version', 'deleted', 'position'));

  global $user_online_id;
  $json = $app->request->getBody();
  $data = json_decode($json, true);
  $todo_online_id = $data["todo_online_id"];
  if ($data["list_online_id"] != null) {
    $list_online_id = $data["list_online_id"];
  } else {
    $list_online_id = null;
  }
  $title = $data["title"];
  $priority = $data["priority"];
  if ($data["due_date"] != null || $data["due_date"] != 0) {
    $due_date = $data["due_date"];
  } else {
    $due_date = null;
  }
  if ($data["reminder_date_time"] != null || $data["reminder_date_time"] != 0) {
    $reminder_date_time = $data["reminder_date_time"];
  } else {
    $reminder_date_time = null;
  }
  if ($data["description"] != null) {
    $description = $data["description"];
  } else {
    $description = null;
  }
  $completed = $data["completed"];
  $row_version = $data["row_version"];
  $deleted = $data["deleted"];
  $position = $data["position"];
  
  $db = new DbHandler();
  $response = array();
  
  $success = $db->createTodo($todo_online_id, $user_online_id, 
          $list_online_id, $title, $priority, $due_date, $reminder_date_time, 
          $description, $completed, $row_version, $deleted, $position);
  
  if ($success) {
    $response["error"] = false;
    $response["message"] = "Todo created successfully.";
    echoResponse(201, $response);
  } else {
    $response["error"] = true;
    $response["message"] = "Failed to create todo. Please try again!";
    echoResponse(500, $response);
  }
});

/*
 * ------------------------- list tábla metódusai ----------------------------
 */

/**
 * Az adott User-hez tartozó összes List lekérése row_version alapján.
 * GET metódus
 * url /list/:row_version
 */
$app->get('/list/:row_version', 'authenticate', function($row_version) {
  global $user_online_id;
  $response = array();
  $db = new DbHandler();

  $lists = $db->getLists($row_version, $user_online_id);

  if ($lists != NULL) {
    $response["error"] = false;
    $response["lists"] = $lists;
    echoResponse(200, $response);
  } else {
    $response["error"] = false;
    $response["lists"] = $lists;
    $response["message"] = "Your local db is up to date.";
    echoResponse(200, $response);
  }
});

/**
 * Az adott List frissítése a megadott adatok alapján.
 * PUT metódus
 * url /list/update
 * @param String $list_online_id A frissítendő List-hez tartozó list_online_id.
 * @param String $category_online_id A frissítendő List-hez tartozó új 
 * category_online_id.
 * @param String $title A frissítendő List-hez tartozó új title.
 * @param Integer $deleted A frissítendő List-hez tartozó új deleted.
 */
// 000webhost.com don't allow PUT and DELETE requests for free accounts
//$app->put('/list/update', 'authenticate', function() use($app) {
$app->post('/list/update', 'authenticate', function() use($app) {
  
  verifyRequiredJSONParams(array('list_online_id', 'title', 'row_version', 'deleted', 'position'));

  global $user_online_id;
  $json = $app->request->getBody();
  $data = json_decode($json, true);
  $list_online_id = $data["list_online_id"];
  if ($data["category_online_id"] != "") {
    $category_online_id = $data["category_online_id"];
  } else {
    $category_online_id = null;
  }
  $title = $data["title"];
  $row_version = $data["row_version"];
  $deleted = $data["deleted"];
  $position = $data["position"];

  $db = new DbHandler();
  $response = array();

  $success = $db->updateList($list_online_id, $user_online_id, 
          $category_online_id, $title, $row_version, $deleted, $position);
  
  if ($success) {
    $response["error"] = false;
    $response["message"] = "List updated successfully.";
    echoResponse(200, $response);
  } else {
    $response["error"] = true;
    $response["message"] = "List failed to update. Please try again!";
    echoResponse(500, $response);
  }
});

/**
 * Az adott List létrehozása a megadott adatokkal.
 * POST metódus
 * url /list/insert
 * @param String $list_online_id A létrehozandó List-hez tartozó 
 * list_online_id.
 * @param String $category_online_id A létrehozandó List-hez tartozó 
 * category_online_id.
 * @param String $title A létrehozandó List-hez tartozó title.
 * @param Integer $deleted A létrehozandó List-hez tartozó deleted.
 */
$app->post('/list/insert', 'authenticate', function() use ($app) {
  
  verifyRequiredJSONParams(array('list_online_id', 'title', 'row_version', 'deleted', 'position'));

  global $user_online_id;
  $json = $app->request->getBody();
  $data = json_decode($json, true);
  $list_online_id = $data["list_online_id"];
  if ($data["category_online_id"] != "") {
    $category_online_id = $data["category_online_id"];
  } else {
    $category_online_id = null;
  }
  $title = $data["title"];
  $row_version = $data["row_version"];
  $deleted = $data["deleted"];
  $position = $data["position"];
  
  $db = new DbHandler();
  $response = array();
  
  $success = $db->createList($list_online_id, $user_online_id, 
          $category_online_id, $title, $row_version, $deleted, $position);
  
  if ($success) {
    $response["error"] = false;
    $response["message"] = "List created successfully.";
    echoResponse(201, $response);
  } else {
    $response["error"] = true;
    $response["message"] = "Failed to create list. Please try again!";
    echoResponse(500, $response);
  }
});

/*
 * ------------------------ category tábla metódusai -------------------------
 */

/**
 * Az adott User-hez tartozó összes Category lekérése row_version alapján.
 * GET metódus
 * url /category/:row_version
 */
$app->get('/category/:row_version', 'authenticate', function($row_version) {
  global $user_online_id;
  $response = array();
  $db = new DbHandler();

  $categories = $db->getCategories($row_version, $user_online_id);

  if ($categories != NULL) {
    $response["error"] = false;
    $response["categories"] = $categories;
    echoResponse(200, $response);
  } else {
    $response["error"] = false;
    $response["categories"] = $categories;
    $response["message"] = "Your local db is up to date.";
    echoResponse(200, $response);
  }
});

/**
 * Az adott Category frissítése a megadott adatok alapján.
 * PUT metódus
 * url /category/update
 * @param String $category_online_id A frissítendő Category-hez tartozó 
 * category_online_id.
 * @param String $title A frissítendő Category-hez tartozó új title.
 * @param Integer $deleted A frissítendő Category-hez tartozó új deleted.
 */
// 000webhost.com don't allow PUT and DELETE requests for free accounts
//$app->put('/category/update', 'authenticate', function() use($app) {
$app->post('/category/update', 'authenticate', function() use($app) {
  
  verifyRequiredJSONParams(array('category_online_id', 'title', 'row_version', 'deleted', 'position'));

  global $user_online_id;
  $json = $app->request->getBody();
  $data = json_decode($json, true);
  $category_online_id = $data["category_online_id"];
  $title = $data["title"];
  $row_version = $data["row_version"];
  $deleted = $data["deleted"];
  $position = $data["position"];

  $db = new DbHandler();
  $response = array();

  $success = $db->updateCategory($category_online_id, $user_online_id, 
          $title, $row_version, $deleted, $position);
  
  if ($success) {
    $response["error"] = false;
    $response["message"] = "Category updated successfully.";
    echoResponse(200, $response);
  } else {
    $response["error"] = true;
    $response["message"] = "Category failed to update. Please try again!";
    echoResponse(500, $response);
  }
});

/**
 * Az adott Category létrehozása a megadott adatok alapján.
 * POST metódus
 * url /category/insert
 * @param String $category_online_id A létrehozandó Category-hoz tartozó 
 * category_online_id.
 * @param String $title A létrehozandó Category-hoz tartozó title.
 * @param Integer $deleted A létrehozandó Category-hoz tartozó deleted.
 */
$app->post('/category/insert', 'authenticate', function() use ($app) {
  
  verifyRequiredJSONParams(array('category_online_id', 'title', 'row_version', 'deleted', 'position'));

  global $user_online_id;
  $json = $app->request->getBody();
  $data = json_decode($json, true);
  $category_online_id = $data["category_online_id"];
  $title = $data["title"];
  $row_version = $data["row_version"];
  $deleted = $data["deleted"];
  $position = $data["position"];
  
  $db = new DbHandler();
  $response = array();
  
  $success = $db->createCategory($category_online_id, $user_online_id, 
          $title, $row_version, $deleted, $position);
  
  if ($success) {
    $response["error"] = false;
    $response["message"] = "Category created successfully.";
    echoResponse(201, $response);
  } else {
    $response["error"] = true;
    $response["message"] = "Failed to create category. Please try again!";
    echoResponse(500, $response);
  }
});

/*
 * --------------------------- Egyéb metódusok -------------------------------
 */

/**
 * Ellenőrzi a kötelező paraméterek meglétét.
 */
function verifyRequiredParams($required_fields) {
  $error = false;
  $error_fields = "";
  $request_params = array();
  $request_params = $_REQUEST;
  
  if ($_SERVER['REQUEST_METHOD'] == 'PUT' || 
          $_SERVER['REQUEST_METHOD'] == 'POST') {
    $app = \Slim\Slim::getInstance();
    parse_str($app->request()->getBody(), $request_params);
  }
  foreach ($required_fields as $field) {
    if (!isset($request_params[$field]) || 
            strlen(trim($request_params[$field])) <= 0) {
      $error = true;
      $error_fields .= $field . ', ';
    }
  }

  if ($error) {
    // A kötelező mezők hiányoznak vagy üresek.
    // Error json echo-zása és app leállítása.
    $response = array();
    $app = \Slim\Slim::getInstance();
    $response["error"] = true;
    $response["message"] = 'Required field(s) ' . substr($error_fields, 0, -2) 
            . ' is missing or empty';
    echoResponse(400, $response);
    $app->stop();
  }
}

/**
 * Ellenőrzi a kötelező paraméterek meglétét.
 */
function verifyRequiredJSONParams($required_fields) {
  $error = false;
  $error_fields = "";
  $request_params = array();
  $request_params = $_REQUEST;
  
  if ($_SERVER['REQUEST_METHOD'] == 'PUT' || 
          $_SERVER['REQUEST_METHOD'] == 'POST') {
    $app = \Slim\Slim::getInstance();
    $json = $app->request->getBody();
    $request_params = json_decode($json, true);
    // parse_str($app->request()->getBody(), $request_params);
  }
  foreach ($required_fields as $field) {
    if (!isset($request_params[$field]) || 
            strlen(trim($request_params[$field])) <= 0) {
      $error = true;
      $error_fields .= $field . ', ';
    }
  }

  if ($error) {
    // A kötelező mezők hiányoznak vagy üresek.
    // Error json echo-zása és app leállítása.
    $response = array();
    $app = \Slim\Slim::getInstance();
    $response["error"] = true;
    $response["message"] = 'Required field(s) ' . substr($error_fields, 0, -2)
            . ' is missing or empty';
    echoResponse(400, $response);
    $app->stop();
  }
}

/**
 * Json választ echo-z a kliensnek.
 * @param Integer $status_code A http response code.
 * @param String $response A json válasz.
 */
function echoResponse($status_code, $response) {
  $app = \Slim\Slim::getInstance();
  
  $app->status($status_code);

  // A response content type-ját json-ra állítja.
  $app->contentType('application/json');

  echo json_encode($response);
}

$app->run();
?>