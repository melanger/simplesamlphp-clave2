<?php

/**
 * Here we return the metrics which we don't have a history of values for, so the read value is always a live and
 * absolute value.
 */


const SP_METADATA_FILENAME = '/var/www/clave2Bridge/metadata/saml20-sp-remote.php';

$sp_metadata = file_get_contents(SP_METADATA_FILENAME);


$sp_metadata = preg_replace('!/\*.*?\*/!s', '', $sp_metadata);
$sp_metadata = preg_replace('!(\r\n|\r|\n)\h*//[^\r\n]*(\r\n|\r|\n)!', '$1', $sp_metadata);


preg_match_all('/\$metadata\[["\']([^"\']*)["\']]/', $sp_metadata, $matches);
$SP_entityIDs = $matches[1];

$institutions = [];
foreach ($SP_entityIDs as $entityID) {
    $domain = preg_replace('!(http(s)?://)?([^/:]+)(:[0-9]+)?(/)?.*$!', '$3', $entityID);
    if ($domain === null || $domain === '') {
        continue;
    }
    $institution = preg_replace('!^.*?([-a-zA-Z0-9]+\.[a-zA-Z]+)$!', '$1', $domain);

    if ($institution === null || $institution === '') {
        continue;
    }

    $institutions[] = $institution;
}
$institutions = array_unique($institutions);



header('Content-type: text/csv');
header('Content-disposition: attachment; filename = stats_clave_SPs.csv');

$number_sp = sizeof($SP_entityIDs);
echo "number_sp, ${number_sp}\n";


$number_inst = sizeof($institutions);
echo "number_inst, ${number_inst}\n";
