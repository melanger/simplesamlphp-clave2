<?php

/**
 * Assertion consumer service handler for clave authentication source SP
 */


// TODO: I think this is not mandatory. When it works, try to remove it

if (isset($_POST['samlResponseLogout'])) {
    SimpleSAML\Logger::debug(
        'eIDAS - SP.ACS: Accessing SAML 2.0 - eIDAS SP Assertion Consumer Service -- CALLED FOR SLO'
    );

    SimpleSAML\Utils\HTTP::submitPOSTData(SimpleSAML\Module::getModuleURL('clave/sp/bridge-logout.php'), $_POST);
    die();
}







SimpleSAML\Logger::debug('eIDAS - SP.ACS: Accessing SAML 2.0 - eIDAS SP Assertion Consumer Service');


if (! array_key_exists('PATH_INFO', $_SERVER)) {
    throw new SimpleSAML\Error\BadRequest('Missing authentication source ID in assertion consumer service URL');
}
$sourceId = substr($_SERVER['PATH_INFO'], 1);
$source = SimpleSAML\Auth\Source::getById($sourceId, 'SimpleSAML\Module\clave\Auth_Source_SP');


$metadata = $source->getMetadata();
SimpleSAML\Logger::debug('Metadata on acs:' . print_r($metadata, true));


$hostedSP = $metadata->getString('hostedSP', null);
if ($hostedSP === null) {
    throw new SimpleSAML\Error\Exception("'hosted SP' parameter not found in ${sourceId} Auth Source configuration.");
}
$spMetadata = SimpleSAML\Module\clave\Tools::getMetadataSet($hostedSP, 'clave-sp-hosted');
SimpleSAML\Logger::debug('Clave SP hosted metadata: ' . print_r($spMetadata, true));


$remoteIdPMeta = $source->getIdPMetadata();




$SPdialect = $spMetadata->getString('dialect');
$SPsubdialect = $spMetadata->getString('subdialect');




if (! isset($_REQUEST['SAMLResponse'])) {
    throw new SimpleSAML\Error\BadRequest('No SAMLResponse POST param received.');
}

$resp = base64_decode($_REQUEST['SAMLResponse'], true);
SimpleSAML\Logger::debug('Received response: ' . $resp);



$attributes = [];





$eidas = new SimpleSAML\Module\clave\SPlib();

if ($SPdialect === 'eidas') {
    $eidas->setEidasMode();
}


$id = $eidas->getInResponseToFromReq($resp);


$state = SimpleSAML\Auth\State::loadState($id, 'clave:sp:req');
SimpleSAML\Logger::debug('State on ACS:' . print_r($state, true));


if (! array_key_exists('clave:sp:AuthId', $state)) {
    SimpleSAML\Logger::error('clave:sp:AuthId key missing in $state array');
}
if ($state['clave:sp:AuthId'] !== $sourceId) {
    throw new SimpleSAML\Error\Exception(
        'The authentication source id in the URL does not match the authentication source which sent the request '
    );
}




$allowedRespPostParams = $spMetadata->getArray('sp.post.allowed', []);

if ($state['idp:postParams:mode'] === 'forward') {
    $forwardedParams = [];
    foreach ($_POST as $name => $value) {
        if (in_array($name, $allowedRespPostParams, true)) {
            $forwardedParams[$name] = $value;
        }
    }
    $state['idp:postParams'] = $forwardedParams;
} else {
    //TODO: it is expected that these params will be promoted to attrs in the future
    foreach ($_POST as $name => $value) {
        if (in_array($name, $allowedRespPostParams, true)) {
            $attributes[$name] = $value;
        }
    }
}


$expectedIssuers = null;

$keys = $remoteIdPMeta->getArray('keys', null);
if ($keys !== null) {
    foreach ($keys as $key) {
        if (! $key['X509Certificate'] || $key['X509Certificate'] === '') {
            continue;
        }

        $eidas->addTrustedCert($key['X509Certificate']);
    }
}

$certData = $remoteIdPMeta->getString('certData', null);
if ($certData !== null) {
    $eidas->addTrustedCert($certData);
}


$eidas->setValidationContext(
    $id,
    $state['clave:sp:returnPage'],
    $expectedIssuers,
    $state['clave:sp:mandatoryAttrs']
);

$spkeypem = SimpleSAML\Module\clave\Tools::readCertKeyFile($spMetadata->getString('privatekey', null));
$expectEncrypted = $spMetadata->getBoolean('assertions.encrypted', true);
$onlyEncrypted = $spMetadata->getBoolean('assertions.encrypted.only', false);

$eidas->setDecipherParams($spkeypem, $expectEncrypted, $onlyEncrypted);


$eidas->validateStorkResponse($resp);


$statusInfo = '';
if ($eidas->isSuccess($statusInfo)) {
    SimpleSAML\Logger::debug('Authentication Successful');

    //TODO: this in only specific for clave 1.0 maybe for clave-2.0 keep an eye and add it
    if ($SPsubdialect === 'clave-1.0') {
        SimpleSAML\Logger::debug('Adding issuer as attribute usedIdP:' . $eidas->getRespIssuer());
        $attributes['usedIdP'] = [$eidas->getRespIssuer()];
    }


    $attributes = array_merge($attributes, $eidas->getAttributes());

    $statsData = [
        'spEntityID' => $spMetadata->getString('entityid', null),
        'idpEntityID' => $eidas->getRespIssuer(),
        'protocol' => 'saml2-' . $SPdialect,
    ];
    if (isset($state['saml:AuthnRequestReceivedAt'])) {
        $statsData['logintime'] = microtime(true) - $state['saml:AuthnRequestReceivedAt'];
    }
    SimpleSAML\Stats::log('clave:sp:Response', $statsData);


    //Data needed to process the response // TODO: this is specific for this AuthSource. Harmonise with the others, so I can support standard SAML authsource (or offer two ways and try both of them)

    if (isset($_POST['RelayState'])) {
        $state['saml:RelayState'] = $_POST['RelayState'];
    }

    SimpleSAML\Logger::debug('------------------------held relay state?: ' . $state['saml:HeldRelayState']);
    if (isset($state['saml:HeldRelayState'])) {
        $state['saml:RelayState'] = $state['saml:HeldRelayState'];
        SimpleSAML\Logger::debug('------------------------set held relay state: ' . $state['saml:RelayState']);
    }

    $authInstant = new DateTime($eidas->getAuthnInstant());
    $state['AuthnInstant'] = $authInstant->getTimestamp();
    $state['saml:Binding'] = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';
    if ($eidas->getAuthnContextClassRef() !== null
    && $eidas->getAuthnContextClassRef() !== '') {
        $state['saml:AuthnContextClassRef'] = $eidas->getAuthnContextClassRef();
    }


    $nameID = $eidas->getRespNameID();
    if ($nameID !== null && $nameID !== '') {
        $state['saml:sp:NameID'] = $nameID;
    }

    $nameIDFormat = $eidas->getRespNameIDFormat();
    if ($nameIDFormat !== null && $nameIDFormat !== '') {
        $state['saml:NameIDFormat'] = $nameIDFormat;
    }


    $state['eidas:attr:names'] = $eidas->getAttributeNames();
    $state['eidas:raw:assertions'] = $eidas->getRawAssertions();
    $state['eidas:raw:status'] = $eidas->generateStatus($statusInfo);
    $state['eidas:status'] = [
        'MainStatusCode' => $statusInfo['MainStatusCode'],
        'SecondaryStatusCode' => $statusInfo['SecondaryStatusCode'],
        'StatusMessage' => $statusInfo['StatusMessage'],
    ];



    $respAssertions = $eidas->getAssertions();
    $assertionsData = [];

    foreach ($respAssertions as $respAssertion) {
        $assertionData = [];

        if (isset($respAssertion['ID'])) {   // TODO: recycle assertionID or set new (don't set)?
            $assertionData['ID'] = $respAssertion['ID'];
        }

        if (isset($respAssertion['Issuer'])) {
            $assertionData['Issuer'] = $respAssertion['Issuer'];
        }

        if (isset($respAssertion['AuthnStatement']['AuthnInstant'])) {
            $assertionData['AuthnInstant'] = $respAssertion['AuthnStatement']['AuthnInstant'];
        }

        if (isset($respAssertion['AuthnStatement']['AuthnContext'])) {
            $assertionData['AuthnContextClassRef'] = $respAssertion['AuthnStatement']['AuthnContext'];
        }

        if (isset($respAssertion['Subject']['NameID'])) {
            $assertionData['NameID'] = $respAssertion['Subject']['NameID'];
            $assertionData['NameIDFormat'] = SimpleSAML\Module\clave\SPlib::NAMEID_FORMAT_PERSISTENT;
            if (isset($respAssertion['Subject']['NameFormat'])) {
                $assertionData['NameIDFormat'] = $respAssertion['Subject']['NameFormat'];
            }
            if (isset($respAssertion['Subject']['NameQualifier'])) {
                $assertionData['NameQualifier'] = $respAssertion['Subject']['NameQualifier'];
            }
        }

        $idAttrName = $spMetadata->getString('idAttribute', null);

        if ($idAttrName !== null) {
            foreach ($assertionData['attributes'] as $attr) {
                if ($attr['friendlyName'] === $idAttrName
                    || $attr['name'] === $idAttrName) {
                    $assertionData['NameID'] = $attr['values'][0];
                    break;
                }
            }
        }
        $assertionData['attributes'] = [];
        foreach ($respAssertion['Attributes'] as $attr) {
            $assertionData['attributes'][] = [
                'values' => $attr['values'],
                'friendlyName' => $attr['friendlyName'],
                'name' => $attr['Name'],
            ];
        }
        if (isset($state['saml:ConsumerURL'])) {
            $assertionData['Recipient'] = $state['saml:ConsumerURL'];
        }
        if (isset($state['eidas:requestData']['issuer'])) {
            $assertionData['Audience'] = $state['eidas:requestData']['issuer'];
        } // entityId del remote SP
        if (isset($state['saml:RequestId'])) {
            $assertionData['InResponseTo'] = $state['saml:RequestId'];
        }


        $assertionsData[] = $assertionData;
    }

    $state['eidas:struct:assertions'] = $assertionsData;

    $source->handleResponse($state, $remoteIdPMeta->getString('entityID', null), $attributes);
}




if ($statusInfo['MainStatusCode'] === SimpleSAML\Module\clave\SPlib::ATST_NOTAVAIL) {
    //For some reason, Clave may not return a main status code. In that case, we set responder error // TODO: make this conditional to the dialect?
    $statusInfo['MainStatusCode'] = SimpleSAML\Module\clave\SPlib::ST_RESPONDER;
}


$statsData = [
    'spEntityID' => $spMetadata->getString('entityid', null),
    'idpEntityID' => $eidas->getRespIssuer(),
    'protocol' => 'saml2-' . $SPdialect,
    'error' => [
        'Code' => $statusInfo['MainStatusCode'],
        'SubCode' => $statusInfo['SecondaryStatusCode'],
        'Message' => $statusInfo['StatusMessage'],
    ],
];
if (isset($state['saml:AuthnRequestReceivedAt'])) {
    $statsData['logintime'] = microtime(true) - $state['saml:AuthnRequestReceivedAt'];
}
SimpleSAML\Stats::log('clave:sp:Response:error', $statsData);


SimpleSAML\Auth\State::throwException(
    $state,
    new SimpleSAML\Error\Exception('IdP returned failed status: ' . $statusInfo['StatusMessage'])
);
