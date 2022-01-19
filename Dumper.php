<!DOCTYPE html>
<html lang="en">
<head>
  <title>Bastion API - Dumper</title>
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
$sPath      = "bastion-dumper.cache";
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

class IpEr{
  public function Get_Ip(){
    if(!empty($_SERVER['HTTP_CLIENT_IP'])){
      $client_ip = $_SERVER['HTTP_CLIENT_IP'];
    }
    elseif(!empty($_SERVER['HTTP_X_FORWARDED_FOR'])){
      $client_ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    }
    else{
      $client_ip = $_SERVER['REMOTE_ADDR'];
    }
    return  $client_ip;
  }
}

//CLIENT INFORMATIONS
echo "--------------- CLIENT INFORMATIONS ---------------<br>";

if(!empty($_SERVER['HTTP_CLIENT_IP'])) {  
    $client_ip = $_SERVER['HTTP_CLIENT_IP'];  
}
//Wether the IP Adress is from the Proxy
else if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $client_ip = $_SERVER['HTTP_X_FORWARDED_FOR'];  
}  
//Wether the IP Adress is from the Remote Adress
else{  
    $client_ip = $_SERVER['REMOTE_ADDR'];  
}

if(strstr($client_ip,":"))
    $client_ip_type = "IPv6";
else
    $client_ip_type = "IPv4";

echo "Client IP [" . $client_ip_type . "] : " . $client_ip . " <br>";

$client_port = $_SERVER['REMOTE_PORT'];

echo "Client Port : " . $client_port . "<br>";

$client_iper = new IpEr();
$client_ip = $client_iper->Get_Ip();
$client_hostname = gethostbyaddr($client_ip);

echo "Client Hostname : " . $client_hostname . "<br>";

$agent = $_SERVER["HTTP_USER_AGENT"];

if( preg_match('/MSIE (\d+\.\d+);/', $agent) ) {
  echo "Browser : Internet Explorer <br>";
} else if (preg_match('/Chrome[\/\s](\d+\.\d+)/', $agent) ) {
  echo "Browser : Chrome <br>";
} else if (preg_match('/Edge\/\d+/', $agent) ) {
  echo "Browser : Edge <br>";
} else if ( preg_match('/Firefox[\/\s](\d+\.\d+)/', $agent) ) {
  echo "Browser : Firefox <br>";
} else if ( preg_match('/OPR[\/\s](\d+\.\d+)/', $agent) ) {
  echo "Browser : Opera <br>";
} else if (preg_match('/Safari[\/\s](\d+\.\d+)/', $agent) ) {
  echo "Browser : Safari <br>";
}
echo "Full U.A. : " . $agent . "<br>";

//SERVER INFORMATIONS
echo "<br>--------------- SERVER INFORMATIONS ---------------<br>";

$server_name = $_SERVER["SERVER_NAME"];
$server_adress = $_SERVER["SERVER_ADDR"];
$server_software = $_SERVER["SERVER_SOFTWARE"];
$server_protocol = $_SERVER["SERVER_PROTOCOL"];
$server_gateway_interface = $_SERVER["GATEWAY_INTERFACE"];

echo "Server Name : " . $server_name . "<br>";
echo "Server Adress : " . $server_adress . "<br>";
echo "Server Software : " . $server_software . "<br>";
echo "Server Protocol : " . $server_protocol . "<br>";
echo "Server Gateway Interface : " . $server_gateway_interface . "<br>";


//QUERY INFORMATIONS
echo "<br>--------------- QUERY INFORMATIONS ---------------<br>";

$query_request_method = $_SERVER["REQUEST_METHOD"];
$query_request_time = $_SERVER["REQUEST_TIME"];
$query_request_time_float = $_SERVER["REQUEST_TIME_FLOAT"];
$query_document_root = $_SERVER["DOCUMENT_ROOT"];

echo "Request Method : " . $query_request_method . "<br>";
echo "Request Time : " . $query_request_time . "<br>";
echo "Request Time Float : " . $query_request_time_float . "<br>";
echo "Request Document Root : " . $query_document_root . "<br>";

//QUERY HEADERS RAW
echo "<br>--------------- QUERY HEADERS RAW ---------------<br>";

foreach (getallheaders() as $name => $value) {
    echo "$name: $value <br>";
}
?>