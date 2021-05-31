<?php
/**
 * Clave IdP Logout endopint for simpleSAMLphp.
 */


SimpleSAML\Logger::debug('Call to Clave bridge IdP side');


$claveConfig = SimpleSAML\Module\clave\Tools::getMetadataSet('__DYNAMIC:1__', 'clave-idp-hosted');
SimpleSAML\Logger::debug('Clave Idp hosted metadata: ' . print_r($claveConfig, true));

$hostedSP = $claveConfig->getString('hostedSP', null);
if ($hostedSP === null) {
    throw new SimpleSAML\Error\Exception('No clave hosted SP configuration defined in clave bridge configuration.');
}
$hostedSPmeta = SimpleSAML\Module\clave\Tools::getMetadataSet($hostedSP, 'clave-sp-hosted');
SimpleSAML\Logger::debug('Clave SP hosted metadata: ' . print_r($hostedSPmeta, true));


$idpEntityId = $hostedSPmeta->getString('idpEntityID', null);
if ($idpEntityId === null) {
    throw new SimpleSAML\Error\Exception('No clave IdP configuration defined in clave bridge configuration.');
}

$idpMeta = SimpleSAML\Module\clave\Tools::getMetadataSet($idpEntityId, 'clave-idp-remote');
SimpleSAML\Logger::debug('Clave Idp remote metadata (' . $idpEntityId . '): ' . print_r($idpMeta, true));


$providerName = $hostedSPmeta->getString('providerName', null);

$certPath = $hostedSPmeta->getString('certificate', null);
$keyPath = $hostedSPmeta->getString('privatekey', null);

$endpoint = $idpMeta->getString('SingleLogoutService', null);

$returnPage = SimpleSAML\Module::getModuleURL('clave/sp/bridge-logout.php/');


if ($providerName === null) {
    throw new SimpleSAML\Error\Exception('No provider Name defined in clave bridge configuration.');
}
if ($certPath === null || $keyPath === null) {
    throw new SimpleSAML\Error\Exception(
        'No clave certificate or key defined for the SP interface in clave bridge configuration.'
    );
}




$spcertpem = SimpleSAML\Module\clave\Tools::readCertKeyFile($certPath);
$spkeypem = SimpleSAML\Module\clave\Tools::readCertKeyFile($keyPath);







$claveIdP = new SimpleSAML\Module\clave\SPlib();


//TODO Don't know if we should use the standard POST params or
// completely match the Clave specs Standard: SAMLRequest
if (! isset($_REQUEST['samlRequestLogout'])) {
    throw new SimpleSAML\Error\BadRequest('No samlRequestLogout POST param received.');
}

$request = base64_decode($_REQUEST['samlRequestLogout'], true);


$spEntityId = $claveIdP->getSloNameId($request);
SimpleSAML\Logger::debug('SLO request Issuer (SP): ' . $spEntityId);


$spMetadata = SimpleSAML\Module\clave\Tools::getSPMetadata($claveConfig, $spEntityId);
SimpleSAML\Logger::debug('Clave SP remote metadata (' . $spEntityId . '): ' . print_r($spMetadata, true));




$IdPdialect = $spMetadata->getString('dialect', $claveConfig->getString('dialect'));
$IdPsubdialect = $spMetadata->getString('subdialect', $claveConfig->getString('subdialect'));

SimpleSAML\Logger::debug('---------------------->dialect: ' . $IdPdialect);
SimpleSAML\Logger::debug('---------------------->subdialect: ' . $IdPsubdialect);

if ($IdPdialect === 'eidas') {
    $claveIdP->setEidasMode();
}



if ($IdPdialect === 'eidas') {
    $returnPage = SimpleSAML\Module::getModuleURL(
        'clave/sp/clave-acs.php/' . $claveConfig->getString('auth', '')
    ); // TODO: works?
}


$certs = SimpleSAML\Module\clave\Tools::findX509SignCertOnMetadata($spMetadata);

$claveIdP->addTrustedRequestIssuer($spEntityId, $certs);


SimpleSAML\Stats::log('saml:idp:LogoutRequest:recv', [
    'spEntityID' => $spEntityId,
    'idpEntityID' => $claveConfig->getString('issuer', ''),
]);


$claveIdP->validateLogoutRequest($request);

$reqData = $claveIdP->getSloRequestData();

SimpleSAML\Logger::debug('SP SLO Request data: ' . print_r($reqData, true));


if ($endpoint === null) {

    // ****** Build response for the SP *******

    $idpCertPath = $claveConfig->getString('certificate', null);
    $idpKeyPath = $claveConfig->getString('privatekey', null);
    $idpcertpem = SimpleSAML\Module\clave\Tools::readCertKeyFile($idpCertPath);
    $idpkeypem = SimpleSAML\Module\clave\Tools::readCertKeyFile($idpKeyPath);
    if ($idpCertPath === null || $idpKeyPath === null) {
        throw new SimpleSAML\Error\Exception(
            'No clave SSO response signing certificate or key defined for the IdP interface in clave bridge configuration.'
        );
    }

    $issuer = $claveConfig->getString('issuer', 'NOT_SET');

    $destination = $reqData['issuer'];
    $inResponseTo = $reqData['id'];

    $claveIdPresp = new SimpleSAML\Module\clave\SPlib();

    $claveIdPresp->setSignatureKeyParams($idpcertpem, $idpkeypem, SimpleSAML\Module\clave\SPlib::RSA_SHA256);
    $claveIdPresp->setSignatureParams(SimpleSAML\Module\clave\SPlib::SHA256, SimpleSAML\Module\clave\SPlib::EXC_C14N);

    $respStatus = [];
    $respStatus['MainStatusCode'] = SimpleSAML\Module\clave\SPlib::ST_SUCCESS;
    $respStatus['SecondaryStatusCode'] = null;

    $spResponse = $claveIdPresp->generateSLOResponse($inResponseTo, $issuer, $respStatus, $destination);

    SimpleSAML\Stats::log('saml:idp:LogoutResponse:sent', [
        'spEntityID' => $destination,
        'idpEntityID' => $issuer,
        'partial' => true,
    ]);

    $post = [
        'samlResponseLogout' => base64_encode($spResponse),
    ];
    SimpleSAML\Utils\HTTP::submitPOSTData($destination, $post);
}






//**** Build request for clave *******


$claveSP = new SimpleSAML\Module\clave\SPlib();

if ($IdPdialect === 'eidas') {
    $claveSP->setEidasMode();
}

$claveSP->setSignatureKeyParams($spcertpem, $spkeypem, SimpleSAML\Module\clave\SPlib::RSA_SHA256);
$claveSP->setSignatureParams(SimpleSAML\Module\clave\SPlib::SHA256, SimpleSAML\Module\clave\SPlib::EXC_C14N);


$state = [];
$state['sp:slo:request'] = $reqData;
$state['bridge:slo:returnPage'] = $returnPage;

$id = SimpleSAML\Auth\State::saveState($state, 'clave:bridge:slo:req', true);
SimpleSAML\Logger::debug('Generated Req ID: ' . $id);




$req = base64_encode($claveSP->generateSLORequest($providerName, $endpoint, $returnPage, $id));
SimpleSAML\Logger::debug('Generated LogoutReq: ' . $req);


SimpleSAML\Stats::log('saml:idp:LogoutRequest:sent', [
    'spEntityID' => $hostedSPmeta->getString('entityid'),
    'idpEntityID' => $idpMeta->getString('SingleSignOnService'),
]);


//Redirect
$post = [
    'samlRequestLogout' => $req,
    //TODO: try to restore this if it doesn't go
    //'logoutRequest'  => $req,
    'country' => 'ES',
    // TODO: added when comparing with the kit. see if it can be removed
    'RelayState' => 'dummystate',
    // TODO: added when comparing with the kit. see if you can remove it. If it has to stay, try to propagate it as I do with sso

];

SimpleSAML\Logger::debug('post: ' . print_r($post, true));


SimpleSAML\Utils\HTTP::submitPOSTData($endpoint, $post);
