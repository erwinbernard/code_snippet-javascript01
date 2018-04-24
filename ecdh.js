var elliptic_curve = {
  encrypt: function ($plaintext, $arg_publickey) {
    // Subsequent calls will change eb_serverpkey[$arg_idmethod] and eb_encrypt[$arg_idmethod]
    var $server_publickey = new Uint8Array(JSON.parse('[' + $arg_publickey + ']'));
    // create Random Curve Key
    var $curvekey = new Uint8Array(32);
    window.crypto.getRandomValues($curvekey);
    $client_pair = axlsign.generateKeyPair($curvekey);
    var $client_sharedkey = axlsign.sharedKey($client_pair['private'], $server_publickey);  // Encryption Password
    // create IV from $client_sharedkey + $client_pair['public']
    var $client_iv = axlsign.sharedKey($client_sharedkey, $client_pair['public']);
    // Note: Client Public Key should Not be included in the Plain Text as Server will not be able to decrypt 
    // the Encrypted Text since Client Public Key is needed to get the Shared Key used in encrypting the Plaintext
    // Merge Plaintext checksum (first 32bytes) at the front + Plaintext
    $plaintext = sha512.hmac($client_sharedkey, $plaintext) + $plaintext;
    var $aescbc = new aesjs.ModeOfOperation.cbc($client_sharedkey, $client_iv.slice(0, 16)); // get only the first 16 bytes
    var $encryptedtext = $aescbc.encrypt(aesjs.padding.pkcs7.pad(aesjs.utils.utf8.toBytes($plaintext)));
    // Merge JS Binary Data to Send = $client_pair['public'] (first 32bytes) + $encryptedtext
    var $mergecrypt = window.btoa($client_pair['public'] + ',' + $encryptedtext);
    return [$mergecrypt, $client_sharedkey];
  },
  
  decrypt: function ($cpkeyencryptedtext, $client_sharedkey) {
    // Decode base-64 encoded string
    $cpkeyencryptedtext = window.atob($cpkeyencryptedtext);
    // aesjs.utils.hex.fromBytes($encryptedtext) 
    // $encryptedtext = aesjs.utils.hex.toBytes(encryptedHex); // convert Hex to Bytes
    var $encryptedtext = JSON.parse("[" + $cpkeyencryptedtext + "]");
    var $client_sharedkey = $client_sharedkey;
    var $client_publickey = $encryptedtext.slice(0, 32);
    $encryptedtext = $encryptedtext.slice(32);
    var $client_iv = axlsign.sharedKey($client_sharedkey, new Uint8Array($client_publickey));
    $client_iv = $client_iv.slice(0, 16); // get the first 16bytes
    var aesCbc = new aesjs.ModeOfOperation.cbc($client_sharedkey, $client_iv);
    var decryptedBytes = aesCbc.decrypt(new Uint8Array($encryptedtext));
    var decryptedText = aesjs.padding.pkcs7.strip(decryptedBytes);
    decryptedText = aesjs.utils.utf8.fromBytes(decryptedText);
    var decryptedhash = decryptedText.slice(0, 128);
    decryptedText = decryptedText.slice(128);
    if (decryptedhash !== sha512.hmac($client_sharedkey, decryptedText)) {
      decryptedText = null;
    }
    return decryptedText;
  }
};
