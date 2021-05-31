<?php

/**
 * Logout acs endpoint (response handler) for clave authentication source SP
 */

SimpleSAML\Logger::debug('Call to Clave auth source logout-comeback');


$sourceId = substr($_SERVER['PATH_INFO'], 1);
$source = SimpleSAML\Auth\Source::getById($sourceId, 'SimpleSAML\Module\clave\Auth_Source_SP');

$spMetadata = $source->getMetadata();
SimpleSAML\Logger::debug('Metadata on acs:' . print_r($spMetadata, true));


$hostedSP = $spMetadata->getString('hostedSP', null);
if ($hostedSP === null) {
    throw new SimpleSAML\Error\Exception(
        'No clave hosted SP configuration defined in clave auth source configuration.'
    );
}
$hostedSPmeta = SimpleSAML\Module\clave\Tools::getMetadataSet($hostedSP, 'clave-sp-hosted');
SimpleSAML\Logger::debug('Clave SP hosted metadata: ' . print_r($hostedSPmeta, true));

$spEntityId = $hostedSPmeta->getString('entityid', null);



if (! isset($_REQUEST['samlResponseLogout'])) {
    throw new SimpleSAML\Error\BadRequest('No samlResponseLogout POST param received.');
}

$resp = base64_decode($_REQUEST['samlResponseLogout'], true);
SimpleSAML\Logger::debug('Received response: ' . $resp);



$clave = new SimpleSAML\Module\clave\SPlib();


$id = $clave->getInResponseToFromReq($resp);


$state = SimpleSAML\Auth\State::loadState($id, 'clave:sp:slo:req');
SimpleSAML\Logger::debug('State on logout-return:' . print_r($state, true));



$remoteIdPMeta = $source->getIdPMetadata();

//Not properly set by Clave, so ignoring it.
$expectedIssuers = null;





$keys = $remoteIdPMeta->getArray('keys', null);
if ($keys !== null) {
    foreach ($keys as $key) {
        if (! $key['X509Certificate'] || $key['X509Certificate'] === '') {
            continue;
        }

        $clave->addTrustedCert($key['X509Certificate']);
    }
}

$certData = $remoteIdPMeta->getString('certData', null);
if ($certData !== null) {
    $clave->addTrustedCert($certData);
}





$clave->setValidationContext($id, $state['clave:sp:slo:returnPage'], $expectedIssuers);

if (! $clave->validateSLOResponse($resp)) {
    SimpleSAML\Logger::warning('Unsuccessful logout. Status was: ' . print_r($clave->getResponseStatus(), true));
}


$statsData = [
    'spEntityID' => $spEntityId,
    'idpEntityID' => $clave->getRespIssuer(),
];
$errInfo = '';
if (! $clave->isSuccess($errInfo)) {
    $statsData['error'] = $errInfo['MainStatusCode'];
}
SimpleSAML\Stats::log('saml:idp:LogoutResponse:recv', $statsData);




$state['saml:sp:LogoutStatus'] = $clave->getResponseStatus();
SimpleSAML\Auth\Source::completeLogout($state);
