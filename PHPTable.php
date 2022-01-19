<!DOCTYPE html>
<html lang="en">
<head>
  <title>Bastion API - PHPTable</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="keywords" content="Security, Bastion, sécurité, développeur, web, développement, dév, Adler, Alexandre, MEHRING, Alexandre MEHRING C, C++, Python, PHP">
  <meta name="author" content="Bastion">
  <link rel="icon" type="image/png" href="Images/Logo.png"/>
  <link rel="stylesheet" type="text/css" href="CSS/index.css">
</head>

<?php
$sIPHash    = md5($_SERVER['REMOTE_ADDR']);
$iSecDelay  = 10;
$sPath      = "bastion-phptable.cache";
$bReqAllow  = false;
$r_cooldown = -1;
$sContent   = "";

if ($nFileHandle = fopen($sPath, "c+")) {
    flock($nFileHandle, LOCK_EX);
    $iCurLine = 0;
    while (($sCurLine = fgets($nFileHandle, 4096)) !== FALSE) {
        $iCurLine++;
        $bIsIPRec = strpos($sCurLine, $sIPHash);
        $iLastReq = strtok($sCurLine, '|');
        printf('<div style="display:none">');
        // this record expired anyway:
        if ( (time() - $iLastReq) > $iSecDelay ) {
            // is it also our IP?
            if ($bIsIPRec !== FALSE) {
                $sContent .= time()."|".$sIPHash.PHP_EOL;
                $bReqAllow = true;
            }
        } else {
            if ($bIsIPRec !== FALSE) $r_cooldown = ($iSecDelay-(time()-$iLastReq));
            $sContent .= $sCurLine.PHP_EOL;
        }
        printf('</div>');
    }
}

if ($r_cooldown == -1 && $bReqAllow == false) {
    // no record yet, create one
    $sContent .= time()."|".$sIPHash.PHP_EOL;
    printf('<div style="display:none">');
    echo "Request From New User Successful !";
    printf('</div>');
} elseif ($bReqAllow == true) {
    printf('<div style="display:none">');    
    echo "Request From Old User Successful !";
    printf('</div>');
} else {
    echo "Request Canceled [COOLDOWN] - Please Wait " . $r_cooldown . " Seconds Before Retrying.";
    die();
}

ftruncate($nFileHandle, 0);
rewind($nFileHandle);
fwrite($nFileHandle, $sContent);
flock($nFileHandle, LOCK_UN);
fclose($nFileHandle);

//PHP TABLE DUMP
echo "--------------- PHP TABLE DUMP ---------------<br>";

$indicesServer = array('PHP_SELF',
'GATEWAY_INTERFACE',
'SERVER_ADDR',
'SERVER_NAME',
'SERVER_SOFTWARE',
'SERVER_PROTOCOL',
'REQUEST_METHOD',
'REQUEST_TIME',
'REQUEST_TIME_FLOAT',
'QUERY_STRING',
'DOCUMENT_ROOT',
'HTTP_ACCEPT',
'HTTP_ACCEPT_CHARSET',
'HTTP_ACCEPT_ENCODING',
'HTTP_ACCEPT_LANGUAGE',
'HTTP_CONNECTION',
'HTTP_HOST',
'HTTP_REFERER',
'HTTP_USER_AGENT',
'HTTPS',
'REMOTE_ADDR',
'REMOTE_HOST',
'REMOTE_PORT',
'REMOTE_USER',
'REDIRECT_REMOTE_USER',
'SCRIPT_FILENAME',
'SERVER_ADMIN',
'SERVER_PORT',
'SERVER_SIGNATURE',
'PATH_TRANSLATED',
'SCRIPT_NAME',
'REQUEST_URI',
'PHP_AUTH_DIGEST',
'PHP_AUTH_USER',
'PHP_AUTH_PW',
'AUTH_TYPE',
'PATH_INFO',
'ORIG_PATH_INFO') ;

echo '<table cellpadding="2">' ;
foreach ($indicesServer as $arg) {
    if (isset($_SERVER[$arg])) {
        echo '<tr><td>'.$arg.'</td><td>' . $_SERVER[$arg] . '</td></tr>' ;
    }
    else {
        echo '<tr><td>'.$arg.'</td><td>-</td></tr>' ;
    }
}
echo '</table>' ;
?>