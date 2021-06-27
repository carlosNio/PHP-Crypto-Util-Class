<?php

/**
 * A usefull class that use opessl functions
 * 
 * @author Carlos git@carlosNio
 */


class OsslCrypto
{
    private $destination;
    private $source;
    private $key;
    private $method;
    private $iv;
    private $iv_length;
    private $enc_block;
    private $bytes_blocks;


    public function __construct($method = "aes-128-cbc", $bytes = 16, $blocks = 10000)
    {
        $method = trim(strtolower($method));

        if (!in_array($method, openssl_get_cipher_methods())) {
            throw new \Exception("Undefined method: $method", 3);
        }

        $this->method = $method;
        $this->enc_block = $blocks;
        $this->bytes_blocks = $bytes;
        $this->iv_length = openssl_cipher_iv_length($method);
    }


    public static function random_bytes()
    {
        return base64_encode(openssl_random_pseudo_bytes(17));
    }

    public function setKey(string $key)
    {
        $this->key = substr(sha1($key, true), 0, $this->bytes_blocks);
    }


    public function getKey()
    {
        return $this->key;
    }



    public function setFiles(string $source, string $destination)
    {
        if (!file_exists($source)) {
            throw new Exception("SOURCE FILE: < $source > NOT FOUND");
        }

        $this->source = $source;
        $this->destination = $destination;
    }



    //TEXT ENCRYPT AND DECRYPT

    public function encryptText(string $plaintext, string $password)
    {
        $strong = false;
        $this->iv = openssl_random_pseudo_bytes($this->iv_length, $strong);

        if (!$strong) {
            throw new \Exception("IV not cryptographically strong!");
        }

        $e =  bin2hex(openssl_encrypt($plaintext, $this->method, $password, OPENSSL_RAW_DATA, $this->iv));
        return [$e, $this->method, $this->iv];
    }


    public function decryptText(string $encrypted, string $password, $method = null, $iv = null)
    {
        return openssl_decrypt(hex2bin($encrypted), $method ?? $this->method, $password, OPENSSL_RAW_DATA, $iv ?? $this->iv);
    }


    //FILE ENCRYPT AND DECRYPT
    public  function encryptFile()
    {
        $error = false;
        $this->iv = openssl_random_pseudo_bytes($this->bytes_blocks);

        if (is_null($this->key))
            throw new \Exception("THE KEY CANNOT BE EMPTY");

        if ($fpOut = fopen($this->destination, 'w')) {
            // Put the initialzation vector to the beginning of the file
            fwrite($fpOut, $this->iv);
            if ($fpIn = fopen($this->source, 'rb')) {
                while (!feof($fpIn)) {
                    $plaintext = fread($fpIn, $this->bytes_blocks * $this->enc_block);
                    $ciphertext = openssl_encrypt(
                        $plaintext,
                        $this->method,
                        $this->key,
                        OPENSSL_RAW_DATA,
                        $this->iv
                    );
                    // Use the first 16 bytes of the ciphertext as the next initialization vector
                    $iv = substr($ciphertext, 0, $this->bytes_blocks);
                    fwrite($fpOut, $ciphertext);
                }
                fclose($fpIn);
            } else {
                $error = true;
            }
            fclose($fpOut);
        } else {
            $error = true;
        }
        return $error ? false : $this->destination;
    }






    public  function decryptFile()
    {
        $error = false;

        if (is_null($this->key))
            throw new \Exception("THE KEY CANNOT BE EMPTY");


        if ($fpOut = fopen($this->destination, 'w')) {
            if ($fpIn = fopen($this->source, 'rb')) {
                // Get the initialzation vector from the beginning of the file
                $iv = fread($fpIn, $this->bytes_blocks);
                while (!feof($fpIn)) {
                    $ciphertext = fread($fpIn, $this->bytes_blocks * ($this->enc_block + 1));
                    $plaintext = openssl_decrypt(
                        $ciphertext,
                        $this->method,
                        $this->key,
                        \OPENSSL_RAW_DATA,
                        $iv
                    );
                    // Use the first 16 bytes of the ciphertext as the next initialization vector
                    $iv = substr($ciphertext, 0, $this->bytes_blocks);
                    fwrite($fpOut, $plaintext);
                }
                fclose($fpIn);
            } else {
                $error = true;
            }
            fclose($fpOut);
        } else {
            $error = true;
        }
        return $error ? false : $this->destination;
    }

    //
}
