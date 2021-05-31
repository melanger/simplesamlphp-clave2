<?php
/**
 * The SSOService is part of the SAML 2.0 - eIDAS IdP code, and it receives incoming Authentication Requests from a SAML
 * 2.0 SP, parses, and process it, and then authenticates the user and sends the user back to the SP with an
 * Authentication Response.
 *
 * @author Francisco José Aragó Monzonís, RedIRIS <francisco.arago@externos.rediris.es>
 * @package Clave
 */


//TODO: This is a refactor of the clave-bridge script. Renamed to
// this for compatibility.When heavily tested, replace former with
// link to this one to give backwards compatibility

//TODO: Now, on SSP, metadata sources are parametrised in config
// (whether they come from a PHP file, an XML file, metadata query
// server, database). Integrate it or imitate its use for the
// eIDAS/Clave metadata sources, but for now, keep them simply as
// plain php files.

// TODO: when everything works, rename module and everything to eIDAS, remove clave references but for the specific clave impl.

// TODO: improve SSO and WAYF script to use SSPHP template


// TODO: Implement the publication of IdP side metadata (for the remote SPs) (besides the actual SP side metadata published. Use the same? check if any differences)


SimpleSAML\Logger::debug('eIDAS - IdP.SSOService: Accessing SAML 2.0 - eIDAS IdP endpoint SSOService');

$idpEntityId = '__DYNAMIC:1__';

$hostedIdpMeta = SimpleSAML\Module\clave\Tools::getMetadataSet($idpEntityId, 'clave-idp-hosted');
SimpleSAML\Logger::debug('eIDAS IDP hosted metadata (' . $idpEntityId . '): ' . print_r($hostedIdpMeta, true));


$idp = SimpleSAML\Module\clave\IdP::getById($idpEntityId);



$expectedRequestPostParams = $hostedIdpMeta->getArray('idp.post.allowed', []);

$forwardedParams = [];
foreach ($_POST as $name => $value) {
    if (in_array($name, $expectedRequestPostParams, true)) {
        $forwardedParams[$name] = $value;
    }
}


// TODO: support HTTP-REDIRECT binding (move the post-get part somewhere else? use the SAML2\Binding ?)

if (! array_key_exists('SAMLRequest', $_POST)) {
    throw new SimpleSAML\Error\BadRequest('SAMLRequest POST param not set.');
}
if ($_POST['SAMLRequest'] === null || $_POST['SAMLRequest'] === '') {
    throw new SimpleSAML\Error\BadRequest('SAMLRequest POST param empty.');
}
$authnRequest = $_POST['SAMLRequest'];


$relayState = '';
if (array_key_exists('RelayState', $_POST)) {
    $relayState = $_POST['RelayState'];
}



$authnRequest = base64_decode($authnRequest, true);
SimpleSAML\Logger::debug('Received authnRequest from remote SP: ' . $authnRequest);


$eidas = new SimpleSAML\Module\clave\SPlib();


$spEntityId = $eidas->getIssuer($authnRequest);
if ($spEntityId === '') {
    $spEntityId = $eidas->getProviderName($authnRequest);
}     // TODO: CHECK
SimpleSAML\Logger::debug('Remote SP Issuer: ' . $spEntityId);

$spMetadata = SimpleSAML\Module\clave\Tools::getSPMetadata($hostedIdpMeta, $spEntityId);
SimpleSAML\Logger::debug('Clave SP remote metadata (' . $spEntityId . '): ' . print_r($spMetadata, true));



$IdPdialect = $spMetadata->getString('dialect', $hostedIdpMeta->getString('dialect'));
$IdPsubdialect = $spMetadata->getString('subdialect', $hostedIdpMeta->getString('subdialect'));
if ($IdPdialect === 'eidas') {
    $eidas->setEidasMode();
}


$certs = SimpleSAML\Module\clave\Tools::findX509SignCertOnMetadata($spMetadata);
$eidas->addTrustedRequestIssuer($spEntityId, $certs);



try {
    $eidas->validateStorkRequest($authnRequest);
} catch (Exception $e) {
    throw new SimpleSAML\Error\BadRequest($e->getMessage());
}



$reqData = $eidas->getStorkRequestData();

SimpleSAML\Logger::debug('SP Request data: ' . print_r($reqData, true));


SimpleSAML\Stats::log('clave:idp:AuthnRequest', [
    'spEntityID' => $spEntityId,
    'idpEntityID' => $hostedIdpMeta->getString('issuer', ''),
    'forceAuthn' => true,
    //$reqData['forceAuthn'],
    'isPassive' => $reqData['isPassive'],
    'protocol' => 'saml2-' . $IdPdialect,
    'idpInit' => false,
]);



$authnContext = null;
if (isset($reqData['LoA'])) {
    $authnContext = [
        'AuthnContextClassRef' => [$reqData['LoA']],
        'Comparison' => $reqData['Comparison'],
    ];
}


$idFormat = SimpleSAML\Module\clave\SPlib::NAMEID_FORMAT_UNSPECIFIED;
if (isset($reqData['IdFormat'])) {
    $idFormat = $reqData['IdFormat'];
}

$idAllowCreate = false;
if (isset($reqData['IdAllowCreate'])) {
    $idAllowCreate = $reqData['IdAllowCreate'];
}


//TODO: if implementing multiple dialect classes, make the callback classnames depend on the dialect/subdialect
$state = [

    'Responder' => ['SimpleSAML\Module\clave\IdP_eIDAS', 'sendResponse'],
    SimpleSAML\Auth\State::EXCEPTION_HANDLER_FUNC => ['SimpleSAML\Module\clave\IdP_eIDAS', 'handleAuthError'],
    SimpleSAML\Auth\State::RESTART => SimpleSAML\Utils\HTTP::getSelfURLNoQuery(),

    'SPMetadata' => $spMetadata->toArray(),
    'saml:RelayState' => $relayState,
    'saml:RequestId' => $reqData['id'],
    'saml:IDPList' => $reqData['idplist'],
    'saml:ProxyCount' => null,
    'saml:RequesterID' => [],
    'ForceAuthn' => true,
    'isPassive' => $reqData['isPassive'],
    'saml:ConsumerURL' => $reqData['assertionConsumerService'],
    'saml:Binding' => SAML2\Constants::BINDING_HTTP_POST,
    // TODO: support HTTP_REDIRECT
    'saml:NameIDFormat' => $idFormat,
    'saml:AllowCreate' => $idAllowCreate,
    'saml:Extensions' => $reqData,
    'saml:AuthnRequestReceivedAt' => microtime(true),
    'saml:RequestedAuthnContext' => $authnContext,

    'sp:postParams' => $forwardedParams,
    'idp:postParams:mode' => 'forward',
    'eidas:request' => $authnRequest,
    'eidas:requestData' => $reqData,



];


SimpleSAML\Logger::debug('------------------STATE at SSOService: ' . print_r($state, true));

$idp->handleAuthenticationRequest($state);
