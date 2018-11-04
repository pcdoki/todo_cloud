<?php

class DbHandler {

  private $conn;

  function __construct() {
    //require_once dirname(__FILE__) . './DbConnect.php';
    require_once '../include/DbConnect.php';
    // Adatbázis kapcsolat nyitása.
    $db = new DbConnect();
    $this->conn = $db->connect();
  }
  
  /**
   * Lekéri az adatbázisból a megadott table-höz tartozó következő 
   * row_version-t.
   * @param String $table Az a table, aminek a következő row_version-jét le
   * kérjük.
   * @return Integer A megadott table-höz tartozó következő row_version vagy 
   * semmi.
   */
  public function getNextRowVersion($table, $user_online_id) {
    $stmt = $this->conn->prepare(
            "SELECT "
            . "MAX(row_version) AS max_row_version "
            . "FROM "
            . $table . " "
            . "WHERE "
            . "user_online_id = '" . $user_online_id . "'"
            );
    if ($stmt->execute()) {
      $result = $stmt->get_result()->fetch_assoc();
      $stmt->close();
      return $result["max_row_version"] + 1;
    }
  }

  /* ------------- `user` tábla metódusai ------------------ */

  /**
   * Felvesz az adatbázisba egy User-t a megadott paraméterekkel.
   * @param String $user_online_id A User egyedi azonosítója.
   * @param String $name A User neve.
   * @param String $email A User email címe.
   * @param String $password A User jelszava.
   * @param Integer $deleted A User töröltségi státusza.
   * @return Integer User sikeres beszúrása esetén a USER_CREATED_SUCCESSFULLY 
   * konstans értéke. User sikertelen beszúrása esetén a USER_CREATE_FAILED 
   * konstans értéke. Ha a User már létezik, akkor a USER_ALREADY_EXISTED 
   * konstans értéke.
   */
  public function createUser($user_online_id, $name, $email, $password) {
    //require_once 'PassHash.php';
    require_once '../include/PassHash.php';
    
    if (!$this->isUserExists($email)) {
      $password_hash = PassHash::hash($password);
      $api_key = $this->generateApiKey();

      // A megadott User-t beszúrjuk az adatbázisba.
      $stmt = $this->conn->prepare("INSERT INTO user(user_online_id, name, "
              . "email, password_hash, api_key, deleted) "
              . "values(?, ?, ?, ?, ?, 0)");
      $stmt->bind_param("sssss", $user_online_id, $name, $email, 
              $password_hash, $api_key);
      $result = $stmt->execute();
      $stmt->close();

      // Megvizsgáljuk, sikeres volt-e a beszúrás.
      if ($result) {
        // A User sikeresen beszúrva.
        $response = USER_CREATED_SUCCESSFULLY;
      } else {
        // A User beszúrása sikertelen.
        $response = USER_CREATE_FAILED;
      }
    } else {
      // A User már létezik.
      $response = USER_ALREADY_EXISTED;
    }

    return $response;
  }
  
  public function modifyUserPassword(
          $user_online_id, $current_password, $new_password
          ) {
    //require_once 'PassHash.php';
    require_once '../include/PassHash.php';
    
    if($this->checkCurrentPassword($user_online_id, $current_password)) {
      $password_hash = PassHash::hash($new_password);

      $stmt = $this->conn->prepare(
            "UPDATE "
            . "user "
            . "SET password_hash = ? "
            . "WHERE user_online_id = ?"
            );
      $stmt->bind_param("ss", $password_hash, $user_online_id);
      $stmt->execute();
      $num_affected_rows = $stmt->affected_rows;
      $stmt->close();
      if ($num_affected_rows > 0) {
        return true;
      } else {
        return false;
      }
    } else {
      return null;
    }
  }
  
  public function resetUserPassword($email) {
    //require_once 'PassHash.php';
    require_once '../include/PassHash.php';
    
    $data = $this->getUserOnlineIdAndNameByEmail($email);
    if ($data != null) {
      $user_online_id = $data["user_online_id"];
      $password = bin2hex(openssl_random_pseudo_bytes(8));
      $data['password'] = $password;
      if ($this->modifyUserPassword($user_online_id, $password)) {
        return $data;
      } else {
        return null;
      }      
    } else {
      return null;
    }
  }

    /**
   * Lekéri az adatbázisból a megadott email címhez tartozó User-t.
   * @param String $email A lekérendő User-hez tartozó email cím.
   * @return array A megadott email címhez tartozó User vagy null.
   */
  public function getUserByEmail($email) {
    $stmt = $this->conn->prepare("SELECT user_online_id, name, email, api_key "
            . "FROM user WHERE email = ?");
    $stmt->bind_param("s", $email);
    
    if ($stmt->execute()) {
      $user = $stmt->get_result()->fetch_assoc();
      $stmt->close();
      return $user;
    } else {
      $stmt->close();
      return null;
    }
  }
  
  public function getUserOnlineIdAndNameByEmail($email) {
    $stmt = $this->conn->prepare(
            "SELECT "
            . "user_online_id, name "
            . "FROM "
            . "user "
            . "WHERE "
            . "email = ?"
            );
    $stmt->bind_param("s", $email);
    if ($stmt->execute()) {
      $result = $stmt->get_result()->fetch_assoc();
      $stmt->close();
      return $result;
    } else {
      return null;
    }
  }
  
  /**
   * Lekéri az adatbázisból a megadott api_key-hez tartozó user_online_id-t.
   * @param String $api_key A lekérendő user_online_id-hoz tartozó api_key.
   * @return String A megadott api_key-hez tartozó user_online_id vagy null.
   */
  public function getUserOnlineIdByApiKey($api_key) {
    $stmt = $this->conn->prepare("SELECT user_online_id FROM user WHERE "
            . "api_key = ?");
    $stmt->bind_param("s", $api_key);
    if ($stmt->execute()) {
      $result = $stmt->get_result()->fetch_assoc();
      $stmt->close();
      return $result["user_online_id"];
    } else {
      return null;
    }
  }
  
  /**
   * A megadott bejelentkezési adatok vizsgálata.
   * @param String $email A vizsgálandó email cím.
   * @param String $password A vizsgálandó jelszó.
   * @return boolean Ha a megadott bejelentkezési adatok helyesek, akkor true, 
   * egyébként false.
   */
  public function checkLogin($email, $password) {
    $stmt = $this->conn->prepare("SELECT password_hash FROM user "
            . "WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->bind_result($password_hash);
    $stmt->store_result();
    
    if ($stmt->num_rows > 0) {
      // Létezik felhasználó a megadott email-lel.
      // Jelszó ellenőrzése.
      $stmt->fetch();
      $stmt->close();
      
      require_once 'PassHash.php';
      if (PassHash::check_password($password_hash, $password)) {
        // A megadott jelszó helyes.
        return true;
      } else {
        // A megadott jelszó helytelen.
        return false;
      }
    } else {
      $stmt->close();
      // Nem létezik felhasználó a megadott email-lel.
      return false;
    }
  }
  
    public function checkCurrentPassword($user_online_id, $current_password) {
    $stmt = $this->conn->prepare("SELECT password_hash FROM user "
            . "WHERE user_online_id = ?");
    $stmt->bind_param("s", $user_online_id);
    $stmt->execute();
    $stmt->bind_result($password_hash);
    $stmt->store_result();
    
    if ($stmt->num_rows > 0) {
      // Létezik felhasználó a megadott user_online_id-vel.
      // Jelszó ellenőrzése.
      $stmt->fetch();
      $stmt->close();
      
      require_once 'PassHash.php';
      if (PassHash::check_password($password_hash, $current_password)) {
        // A megadott jelszó helyes.
        return true;
      } else {
        // A megadott jelszó helytelen.
        return false;
      }
    } else {
      $stmt->close();
      // Nem létezik felhasználó a megadott user_online_id-vel.
      return false;
    }
  }
  
  /**
   * Megvizsgálja, hogy az adatbázis tartalmazza-e a megadott api_key-t.
   * @param String $api_key A vizsgálandó api_key.
   * @return boolean Ha az adatbázis tartalmazza a megadott api_key-t, akkor 
   * true, egyébként false.
   */
  public function isApiKeyExists($api_key) {
    $stmt = $this->conn->prepare("SELECT api_key from user WHERE "
            . "api_key = ?");
    $stmt->bind_param("s", $api_key);
    $stmt->execute();
    $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
  }

  /**
   * Megvizsgálja, hogy az adatbázis tartalmaz-e a megadott email címhez tar-
   * tozó User-t.
   * @param String $email A vizsgálandó email cím.
   * @return boolean Ha az adatbázis tartalmaz a megadott email címhez tarto-
   * zó User-t, akkor true, egyébként false.
   */
  private function isUserExists($email) {
    $stmt = $this->conn->prepare("SELECT email from user WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();
    $num_rows = $stmt->num_rows;
    $stmt->close();
    return $num_rows > 0;
  }
  
  /**
   * Egyedi md5 Stringet generál a User számára, ami api_key funkciót tölt be.
   * @return String Az adatbázisban még nem szereplő, egyedi api_key.
   */
  private function generateApiKey() {
    do {
      $api_key = md5(uniqid(rand(), true));
    } while ($this->isApiKeyExists($api_key));
    return $api_key;
  }
  
  /* ------------- `todo` tábla metódusai ------------------ */
  
  /**
   * Lekéri az adatbázisból az összes olyan Todo-t, ami a megadott 
   * user_online_id-hoz tartozik és a row_version-je nagyobb a megadottnál.
   * @param Integer $row_version A lekérendő Todo-khoz tartozó row_version 
   * nagyobb az itt megadott értéknél.
   * @param String $user_online_id A lekérendő Todo-khoz tartozó 
   * user_online_id.
   * @return array Ha az adatbázis tartalmaz a megadott adatoknak megfelelő 
   * Todo-t, akkor a megadott adatoknak eleget tevő Todok, egyébként null.
   */
  public function getTodos($row_version, $user_online_id) {
    $stmt = $this->conn->prepare("SELECT * FROM todo WHERE row_version > ? "
            . "AND user_online_id = ?");
    $stmt->bind_param("is", $row_version, $user_online_id);
    if ($stmt->execute()) {
      $result = $stmt->get_result();
      $stmt->close();
      $todos = array();
      while ($todo = $result->fetch_assoc()) {
        if ($todo["list_online_id"] === null) {
          $todo["list_online_id"] = "";
        }
        if ($todo["due_date"] === null) {
          $todo["due_date"] = 0;
        }
        if ($todo["reminder_date_time"] === null) {
          $todo["reminder_date_time"] = 0;
        }
        if ($todo["description"] === null) {
          $todo["description"] = "";
        }
        array_push($todos, $todo);
      }
      return $todos;
    } else {
      return null;
    }
  }
  
  /**
   * Frissíti az adatbázisban az adott Todo-t a megadott adatokkal.
   * @param String $todo_online_id A frissítendő Todo-hoz tartozó 
   * todo_online_id.
   * @param String $user_online_id A frissítendő Todo-hoz tartozó új 
   * user_online_id.
   * @param String $list_online_id A frissítendő Todo-hoz tartozó új 
   * list_online_id.
   * @param String $title A frissítendő Todo-hoz tartozó új title.
   * @param Integer $priority A frissítendő Todo-hoz tartozó új priority.
   * @param Integer $due_date A frissítendő Todo-hoz tartozó új due_date.
   * @param Integer $reminder_date_time A frissítendő Todo-hoz tartozó új 
   * reminder_date_time.
   * @param String $description A frissítendő Todo-hoz tartozó új description.
   * @param Integer $completed A frissítendő Todo-hoz tartozó új completed.
   * @param Integer $deleted A frissítendő Todo-hoz tartozó új deleted.
   * $param Integer $position
   * @return Integer Siker esetén a frissítendő Todo-hoz tartozó row_version, 
   * egyébként null.
   */
  public function updateTodo($todo_online_id, $user_online_id, 
                  $list_online_id, $title, $priority, $due_date, $reminder_date_time, 
                  $description, $completed, $row_version, $deleted, $position) {
        $stmt = $this->conn->prepare("UPDATE todo SET user_online_id = ?, "
                        . "list_online_id = ?, title = ?, priority = ?, due_date = ?, "
                        . "reminder_date_time = ?, description = ?, "
                        . "completed = ?, row_version = ?, deleted = ?, position = ? "
                        . "WHERE todo_online_id = ?");
        $stmt->bind_param("sssiiisiiiis", $user_online_id, $list_online_id, $title, 
                        $priority, $due_date, $reminder_date_time, $description, 
                        $completed, $row_version, $deleted, $position, $todo_online_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        if ($num_affected_rows > 0) {
          return true;
        } else {
          return false;
        }
  }
  
  /**
   * Létrehozza az adatbázisban az adott Todo-t a megadott adatokkal.
   * @param String $todo_online_id A létrehozandó Todo-hoz tartozó 
   * todo_online_id.
   * @param String $user_online_id A létrehozandó Todo-hoz tartozó 
   * user_online_id.
   * @param String $list_online_id A létrehozandó Todo-hoz tartozó 
   * list_online_id.
   * @param String $title A létrehozandó Todo-hoz tartozó title.
   * @param Integer $priority A létrehozandó Todo-hoz tartozó priority.
   * @param Integer $due_date A létrehozandó Todo-hoz tartozó due_date.
   * @param Integer $reminder_date_time A létrehozandó Todo-hoz tartozó 
   * reminder_date_time.
   * @param String $description A létrehozandó Todo-hoz tartozó description.
   * @param Integer $completed A létrehozandó Todo-hoz tartozó completed.
   * @param Integer $deleted A létrehozandó Todo-hoz tartozó deleted.
   * @param In $position 
   * @return Integer Siker esetén a létrehozott Todo-hoz tartozó row_version, 
   * egyébként null.
   */
  public function createTodo($todo_online_id, $user_online_id, 
          $list_online_id, $title, $priority, $due_date, $reminder_date_time, 
          $description, $completed, $row_version, $deleted, $position) {
    $stmt = $this->conn->prepare("INSERT INTO todo(todo_online_id, "
            . "user_online_id, list_online_id, title, priority, due_date, "
            . "reminder_date_time, description, completed, row_version, "
            . "deleted, position) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssiiisiiii", $todo_online_id, $user_online_id, 
            $list_online_id, $title, $priority, $due_date, $reminder_date_time,
            $description, $completed, $row_version, $deleted, $position);
    $result = $stmt->execute();
    $stmt->close();
    
    // Megvizsgáljuk, hogy sikeres volt-e a beszúrás.
    if ($result) {
      return true;
    } else {
      return false;
    }
  }
  
  /* ------------- `list` tábla metódusai ------------------ */
  
  /**
   * Lekéri az adatbázisból az összes olyan List-et, ami a megadott 
   * user_online_id-hoz tartozik és a row_version-je nagyobb a megadottnál.
   * @param Integer $row_version A lekérendő List-ekhez tartozó row_version 
   * nagyobb az itt megadott értéknél.
   * @param String $user_online_id A lekérendő List-ekhez tartozó 
   * user_online_id.
   * @return array Ha az adatbázis tartalmaz a megadott adatoknak megfelelő 
   * List-et, akkor a megadott adatoknak eleget tevő List-ek, egyébként null.
   */
  public function getLists($row_version, $user_online_id) {
    $stmt = $this->conn->prepare("SELECT * FROM list WHERE row_version > ? "
            . "AND user_online_id = ?");
    $stmt->bind_param("is", $row_version, $user_online_id);
    if ($stmt->execute()) {
      $result = $stmt->get_result();
      $stmt->close();
      $lists = array();
      while ($list = $result->fetch_assoc()) {
        if ($list["category_online_id"] === null) {
          $list["category_online_id"] = "";
        }
        array_push($lists, $list);
      }
      return $lists;
    } else {
      return null;
    }
  }
  
  /**
   * Frissíti az adatbázisban az adott List-et a megadott adatokkal.
   * @param String $list_online_id A frissítendő List-hez tartozó 
   * list_online_id.
   * @param String $user_online_id A frissítendő List-hez tartozó új 
   * user_online_id.
   * @param String $category_online_id A frissítendő List-hez tartozó új 
   * category_online_id.
   * @param String $title A frissítendő List-hez tartozó új title.
   * @param Integer $deleted A frissítendő List-hez tartozó új deleted.
   * $param Integer $position
   * @return Integer Siker esetén a frissített List-hez tartozó row_version, 
   * egyébként null.
   */
  public function updateList($list_online_id, $user_online_id, 
          $category_online_id, $title, $row_version, $deleted, $position) {
    $stmt = $this->conn->prepare("UPDATE list SET user_online_id = ?, "
            . "category_online_id = ?, title = ?, row_version = ?, "
            . "deleted = ?, position = ? WHERE list_online_id = ?");
    $stmt->bind_param("sssiiis", $user_online_id, $category_online_id, $title, 
            $row_version, $deleted, $position, $list_online_id);
    $stmt->execute();
    $num_affected_rows = $stmt->affected_rows;
    $stmt->close();
    if ($num_affected_rows > 0) {
      return true;
    } else {
      return false;
    }
  }
  
  /**
   * Felveszi az adatbázisba az adott List-et a megadott adatokkal.
   * @param String $list_online_id A felveendő List-hez tartozó list_online_id.
   * @param String $user_online_id A felveendő List-hez tartozó user_online_id.
   * @param String $category_online_id A felveendő List-hez tartozó 
   * category_online_id.
   * @param String $title A felveendő List-hez tartozó title.
   * @param Integer $deleted A felveendő List-hez tartozó deleted.
   * @param Integer $position 
   * @return Integer Siker esetén a létrehozott List-hez tartozó row_version, 
   * egyébként null.
   */
  public function createList($list_online_id, $user_online_id, 
          $category_online_id, $title, $row_version, $deleted, $position) {
    $stmt = $this->conn->prepare("INSERT INTO list(list_online_id, "
            . "user_online_id, category_online_id, title, row_version, "
            . "deleted, position) values(?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssiii", $list_online_id, $user_online_id, 
            $category_online_id, $title, $row_version, $deleted, $position);
    $result = $stmt->execute();
    $stmt->close();
    
    // Megvizsgáljuk, sikeres volt-e a beszúrás.
    if ($result) {
      return true;
    } else {
      return false;
    }
  }
  
  /* ------------- `category` tábla metódusai ------------------ */
  
  /**
   * Lekéri az adatbázisból az összes olyan Category-t, ami a megadott 
   * user_online_id-hoz tartozik és a row_version-je nagyobb a megadottnál.
   * @param Integer $row_version A lekérendő Category-khez tartozó row_version 
   * nagyobb a megadottnál.
   * @param String $user_online_id A lekérendő Category-khez tartozó 
   * user_online_id.
   * @return array Ha az adatbázis tartalmaz a megadott adatoknak megfelelő 
   * Category-t, akkor a megadott adatoknak eleget tevő Category-k, egyébként 
   * null.
   */
  public function getCategories($row_version, $user_online_id) {
    $stmt = $this->conn->prepare("SELECT * FROM category WHERE row_version > ? "
            . "AND user_online_id = ?");
    $stmt->bind_param("is", $row_version, $user_online_id);
    if ($stmt->execute()) {
      $result = $stmt->get_result();
      $stmt->close();
      $categories = array();
      while ($category = $result->fetch_assoc()) {
        array_push($categories, $category);
      }
      return $categories;
    } else {
      return null;
    }
  }
  
  /**
   * Frissíti az adatbázisban az adott Category-t a megadott adatokkal.
   * @param String $category_online_id A frissítendő Category-hoz tartozó 
   * category_online_id.
   * @param String $user_online_id A frissítendő Category-hoz tartozó új 
   * user_online_id.
   * @param String $title A frissítendő Category-hoz tartozó új title.
   * @param Integer $deleted A frissítendő Category-hoz tartozó új deleted.
   * $param Integer $position
   * @return Integer Siker esetén a frissített Category-hez tartozó 
   * row_version, egyébként null.
   */
  public function updateCategory($category_online_id, $user_online_id, 
          $title, $row_version, $deleted, $position) {
    $stmt = $this->conn->prepare("UPDATE category SET user_online_id = ?, "
            . "title = ?, row_version = ?, deleted = ?, position = ? WHERE "
            . "category_online_id = ?");
    $stmt->bind_param("ssiiis", $user_online_id, $title, $row_version, $deleted, 
            $position, $category_online_id);
    $stmt->execute();
    $num_affected_rows = $stmt->affected_rows;
    $stmt->close();
    if ($num_affected_rows > 0) {
      return true;
    } else {
      return false;
    }
  }
  
  /**
   * Felveszi az adatbázisba az adott Category-t a megadott adatokkal.
   * @param String $category_online_id A felveendő Category-hoz tartozó 
   * category_online_id.
   * @param String $user_online_id  A felveendő Category-hoz tartozó 
   * user_online_id.
   * @param String $title A felveendő Category-hoz tartozó title.
   * @param Integer $deleted A felveendő Category-hoz tartozó deleted.
   * @param Integer $position 
   * @return Integer Siker esetén a létrehozott Category-hoz tartozó 
   * row_version, egyébként null.
   */
  public function createCategory($category_online_id, $user_online_id, 
          $title, $row_version, $deleted, $position) {
    $stmt = $this->conn->prepare("INSERT INTO category(category_online_id, "
            . "user_online_id, title, row_version, deleted, position) "
            . "values(?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("sssiii", $category_online_id, $user_online_id, $title, 
            $row_version, $deleted, $position);
    $result = $stmt->execute();
    $stmt->close();
    
    // Megvizsgáljuk, sikeres volt-e a beszúrás.
    if ($result) {
      return true;
    } else {
      return false;
    }
  }

}

?>