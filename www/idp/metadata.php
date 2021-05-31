<?php

/**
 * Metadata service for eIDAS IdP
 */




$claveConfig = SimpleSAML\Module\clave\Tools::getMetadataSet('__DYNAMIC:1__', 'clave-idp-hosted');
SimpleSAML\Logger::debug('Clave Idp hosted metadata: ' . print_r($claveConfig, true));



$metadataUrl = SimpleSAML\Module::getModuleURL('clave/idp/metadata.php');

$ssoserviceurl = SimpleSAML\Module::getModuleURL('clave/idp/clave-bridge.php');

$idpcertpem = SimpleSAML\Module\clave\Tools::readCertKeyFile($claveConfig->getString('certificate', null));
$idpkeypem = SimpleSAML\Module\clave\Tools::readCertKeyFile($claveConfig->getString('privatekey', null));




$eidas = new SimpleSAML\Module\clave\SPlib();

$eidas->setEidasMode();


$eidas->setSignatureKeyParams($idpcertpem, $idpkeypem, SimpleSAML\Module\clave\SPlib::RSA_SHA512);
$eidas->setSignatureParams(SimpleSAML\Module\clave\SPlib::SHA512, SimpleSAML\Module\clave\SPlib::EXC_C14N);

$eidas->setServiceProviderParams('', $metadataUrl, '');


header('Content-type: application/xml');
echo $eidas->generateIdPMetadata($ssoserviceurl);
