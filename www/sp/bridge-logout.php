<?php

/**
 * Logout acs endpoint (response handler) for clave bridge SP
 */

$claveConfig = SimpleSAML\Module\clave\Tools::getMetadataSet('__DYNAMIC:1__', 'clave-idp-hosted');
SimpleSAML\Logger::debug('Clave Idp hosted metadata: ' . print_r($claveConfig, true));


$idpEntityId = $claveConfig->getString('claveIdP', null);
if ($idpEntityId === null) {
    throw new SimpleSAML\Error\Exception('No clave IdP configuration defined in clave bridge configuration.');
}
$idpMetadata = SimpleSAML\Module\clave\Tools::getMetadataSet($idpEntityId, 'clave-idp-remote');


$hostedSP = $claveConfig->getString('hostedSP', null);
if ($hostedSP === null) {
    throw new SimpleSAML\Error\Exception(
        'No clave hosted SP configuration defined in clave auth source configuration.'
    );
}
$hostedSPmeta = SimpleSAML\Module\clave\Tools::getMetadataSet($hostedSP, 'clave-sp-hosted');
SimpleSAML\Logger::debug('Clave SP hosted metadata: ' . print_r($hostedSPmeta, true));

$spEntityId = $hostedSPmeta->getString('entityid', null);



$expectedIssuers = null;


$certPath = $claveConfig->getString('certificate', null);
$keyPath = $claveConfig->getString('privatekey', null);
$spcertpem = SimpleSAML\Module\clave\Tools::readCertKeyFile($certPath);
$spkeypem = SimpleSAML\Module\clave\Tools::readCertKeyFile($keyPath);
if ($certPath === null || $keyPath === null) {
    throw new SimpleSAML\Error\Exception(
        'No clave SSO response signing certificate or key defined for the IdP interface in clave bridge configuration.'
    );
}


$issuer = $claveConfig->getString('issuer', 'NOT_SET');



// ****** Handle response from the IdP *******


if (! isset($_REQUEST['samlResponseLogout'])) {
    throw new SimpleSAML\Error\BadRequest('No samlResponseLogout POST param received.');
}

$resp = base64_decode($_REQUEST['samlResponseLogout'], true);
SimpleSAML\Logger::debug('Received response: ' . $resp);


$claveSP = new SimpleSAML\Module\clave\SPlib();


$id = $claveSP->getInResponseToFromReq($resp);


$state = SimpleSAML\Auth\State::loadState($id, 'clave:bridge:slo:req');
SimpleSAML\Logger::debug('State on slo-return:' . print_r($state, true));



$keys = $idpMetadata->getArray('keys', null);
if ($keys !== null) {
    foreach ($keys as $key) {
        if (! $key['X509Certificate'] || $key['X509Certificate'] === '') {
            continue;
        }

        $claveSP->addTrustedCert($key['X509Certificate']);
    }
}

$certData = $idpMetadata->getString('certData', null);
if ($certData !== null) {
    $claveSP->addTrustedCert($certData);
}


$claveSP->setValidationContext($id, $state['bridge:slo:returnPage'], $expectedIssuers);


if (! $claveSP->validateSLOResponse($resp)) {
    SimpleSAML\Logger::warning('Unsuccessful logout. Status was: ' . print_r($claveSP->getResponseStatus(), true));
}

$respStatus = $claveSP->getResponseStatus();


$statsData = [
    'spEntityID' => $spEntityId,
    'idpEntityID' => $claveSP->getRespIssuer(),
];
$errInfo = '';
if (! $claveSP->isSuccess($errInfo)) {
    $statsData['error'] = $errInfo['MainStatusCode'];
}
SimpleSAML\Stats::log('saml:idp:LogoutResponse:recv', $statsData);



// ****** Build response for the SP *******



$destination = $state['sp:slo:request']['issuer'];
$inResponseTo = $state['sp:slo:request']['id'];

$claveIdP = new SimpleSAML\Module\clave\SPlib();

$claveIdP->setSignatureKeyParams($spcertpem, $spkeypem, SimpleSAML\Module\clave\SPlib::RSA_SHA256);
$claveIdP->setSignatureParams(SimpleSAML\Module\clave\SPlib::SHA256, SimpleSAML\Module\clave\SPlib::EXC_C14N);

$spResponse = $claveIdP->generateSLOResponse($inResponseTo, $issuer, $respStatus, $destination);


SimpleSAML\Stats::log('saml:idp:LogoutResponse:sent', [
    'spEntityID' => $destination,
    'idpEntityID' => $issuer,
    'partial' => true,
]);


$post = [
    'samlResponseLogout' => base64_encode($spResponse),
];
SimpleSAML\Utils\HTTP::submitPOSTData($destination, $post);
