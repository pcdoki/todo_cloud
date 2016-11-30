<?php

/**
 * Adatbázis kapcsolat kezelése.
 */
class DbConnect {

  private $conn;

  function __construct() {
    
  }

  /**
   * Adatbázis kapcsolat létesítése.
   * @return mysqli (adatbázis kapcsolat kezelője)
   */
  function connect() {
    include_once dirname(__FILE__) . './Config.php';

    // Kapcsolódás a mysql adatbázishoz.
    $this->conn = new mysqli(DB_HOST, DB_USERNAME, DB_PASSWORD, DB_NAME);

    // Adatbázis kapcsolódási hiba vizsgálata.
    if (mysqli_connect_errno()) {
      echo "Failed to connect to MySQL: " . mysqli_connect_error();
    }

    return $this->conn;
  }

}

?>