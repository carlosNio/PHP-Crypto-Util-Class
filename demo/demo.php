<?php
require "../class/OsslCrypto.php";


// RANDOM BYTE

$token = OsslCrypto::random_bytes();


// TEXT
$ossl = new OsslCrypto();

$text = "hey PHP developer";
$key = "123454321";

// encrypt the text
$encrypted = $ossl->encryptText($text , $key);
// result: a array
// [0] - the encrypted text
// [1] - the method used
// [2] - the inicialization vector


// decrypt text text on same instance
$decrypted = $ossl->decryptText($encrypted[0] , $key);

// decrypt text text on another instance
$ossl2 = new OsslCrypto();
$decrypted = $ossl2->decryptText($encrypted[0] , $key); // will not result

// the method and the inicialization vector must be given
// give the method if the current instance are using a diferent method from the first that generete 
$decrypted = $ossl2->decryptText($encrypted[0] , $key , $encrypted[1] , $encrypted[2]);



// FILES

$o = new OsslCrypto();

$key = "secret key"; // make sure that was created by a random function like random_bytes()

$from = "files/db.json";
$to = "files/db.json.enc";

$o->setKey($key);
$o->setFiles($from , $to);
$path = $o->encryptFile(); //db.json.enc if success , false if fails

//later
$from = "files/db.json.enc";
$to = "files/db.json.dec";
$o->setKey($key);
$o->setFiles($from , $to);
$path = $o->decryptFile(); //db.json.dec if success , false if fails