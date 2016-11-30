<?php

/**
 * PasswordHash-t készít blowfish algoritmussal.
 */
class PassHash {
 
    // Blowfish.
    private static $algo = '$2a';
    // Cost paraméter.
    private static $cost = '$10';
 
    /**
     * Egyedi Salt-ot készít.
     * @return String Egyedi Salt.
     */
    public static function unique_salt() {
        return substr(sha1(mt_rand()), 0, 22);
    }
 
    /**
     * Hash-t generál a megadott password-ből.
     * @param String $password A password, amiből a hash-t generáljuk.
     * @return String A megadott password-ből generált hash.
     */
    public static function hash($password) {
 
        return crypt($password, self::$algo .
                self::$cost .
                '$' . self::unique_salt());
    }
 
    /**
     * Megvizsgálja, hogy a megadott hash a megadott jelszóhoz tartozik-e.
     * @param String $hash Összehasonlítandó a megadott password-ből generált 
     * hash-hel.
     * @param String $password A belőle generált hash összehasonlítandó a meg-
     * adott hash-hel.
     * @return boolean Ha a megadott hash a megadott password-höz tartozik, 
     * akkor true, egyébként false.
     */
    public static function check_password($hash, $password) {
        $full_salt = substr($hash, 0, 29);
        $new_hash = crypt($password, $full_salt);
        return ($hash == $new_hash);
    }
 
}
 
?>