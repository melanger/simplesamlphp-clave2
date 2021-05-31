<?php

/**
 * Metadata service for eIDAS SP Expects, at the end of the URL, a string: [acs-ID]/[clave-sp-hosted-ID]/[authsource-ID]
 * ...sp/metadata.php/bridge/hostedSpID/authSource
 */


$pathInfoStr = str_replace('.', '', substr($_SERVER['PATH_INFO'], 1));
$pathInfo = explode('/', $pathInfoStr);

$acsID = '';
$hostedSpId = '';
$authSource = '';
if (count($pathInfo) >= 1) {
    $acsID = $pathInfo[0];
}
if (count($pathInfo) >= 2) {
    $hostedSpId = $pathInfo[1];
}
if (count($pathInfo) >= 3) {
    $authSource = $pathInfo[2];
}

if ($acsID === null || $acsID === '') {
    throw new SimpleSAML\Error\Exception('No eIDAS ACS ID provided on the url path info.');
}

if ($hostedSpId === null || $hostedSpId === '') {
    throw new SimpleSAML\Error\Exception('No eIDAS hosted SP ID provided on the url path info.');
}
$hostedSPmeta = SimpleSAML\Module\clave\Tools::getMetadataSet($hostedSpId, 'clave-sp-hosted');
SimpleSAML\Logger::debug('Clave SP hosted metadata: ' . print_r($hostedSPmeta, true));


$metadataUrl = SimpleSAML\Module::getModuleURL('clave/sp/metadata.php/' . $pathInfoStr);

$returnPage = SimpleSAML\Module::getModuleURL('clave/sp/' . $acsID . '-acs.php/' . $authSource);

$spcertpem = SimpleSAML\Module\clave\Tools::readCertKeyFile($hostedSPmeta->getString('certificate', null));
$spkeypem = SimpleSAML\Module\clave\Tools::readCertKeyFile($hostedSPmeta->getString('privatekey', null));




$eidas = new SimpleSAML\Module\clave\SPlib();

$eidas->setEidasMode();


$eidas->setSignatureKeyParams($spcertpem, $spkeypem, SimpleSAML\Module\clave\SPlib::RSA_SHA512);
$eidas->setSignatureParams(SimpleSAML\Module\clave\SPlib::SHA512, SimpleSAML\Module\clave\SPlib::EXC_C14N);

$eidas->setServiceProviderParams('', $metadataUrl, $returnPage);


header('Content-type: application/xml');
echo $eidas->generateSPMetadata();
