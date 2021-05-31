<?php

namespace SimpleSAML\Module\clave;

use SAML2\Binding;
use SAML2\Response;
use SimpleSAML\Configuration;
use SimpleSAML\Error\Exception;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Module\saml\Error;
use SimpleSAML\Module\saml\Message;
use SimpleSAML\Stats;
use SimpleSAML\Utils\HTTP;

/**
 * The specific parts of the IdP for SAML 2.0 eIDAS Protocol and deployment. Internally it will rely on my SPlib, but
 * this will implement the proper SSPHP API to be called by the class that extends SimpleSAML_IdP
 *
 * @author Francisco José Aragó Monzonís, RedIRIS <francisco.arago@externos.rediris.es>
 * @package Clave
 */


// TODO: when everything is working, rename the SPlib and all its internal and external references to eIDASlib

class IdP_eIDAS
{
    /**
     * Send a response to the SP.
     *
     * @param array $state The authentication state.
     * @throws Exception
     */
    public static function sendResponse(array $state)
    {
        if (! isset($state['Attributes'])) {
            Logger::error('Missing $state["Attributes"]');
        }
        if (! isset($state['SPMetadata'])) {
            Logger::error('Missing $state["SPMetadata"]');
        }
        if (! isset($state['saml:ConsumerURL'])) {
            Logger::error('Missing $state["saml:ConsumerURL"]');
        }
        if (! array_key_exists('saml:RequestId', $state)) {
            Logger::error('saml:RequestId key missing in $state array');
        }
        if (! array_key_exists('saml:RelayState', $state)) {
            Logger::error('saml:RelayState key missing in $state array');
        }

        $spMetadata = Configuration::loadFromArray($state['SPMetadata']);
        $spEntityId = $spMetadata->getString('entityid', null);
        Logger::debug('eIDAS SP remote metadata (' . $spEntityId . '): ' . print_r($spMetadata, true));

        Logger::debug('Sending eIDAS Response to ' . var_export($spEntityId, true));

        $relayState = $state['saml:RelayState'];
        Logger::debug('------------------Relay State on sendResponse: ' . $state['saml:RelayState']);

        $idp = IdP::getByState($state);

        $idpMetadata = $idp->getConfig();

        //We clone the assertions on the response, as they are signed // TODO: decission needs to be taken later. move to a specific variable.
        //on source (signature kept for legal reasons).    // TODO: make this dialect dependent? or just hierachize assertion building as I did below?
        $rawassertions = null;
        if (isset($state['eidas:raw:assertions'])) {
            $rawassertions = $state['eidas:raw:assertions'];
        }

        $structassertions = null;
        if (isset($state['eidas:struct:assertions'])) {
            $structassertions = $state['eidas:struct:assertions'];
        }

        $singleassertion = null;
        if (isset($state['Attributes'])) {
            $singleassertion = $state['Attributes'];
        }

        $reqData = $state['eidas:requestData'];

        $hiCertPath = $idpMetadata->getString('certificate', null);
        $hiKeyPath = $idpMetadata->getString('privatekey', null);
        if ($hiCertPath === null || $hiKeyPath === null) {
            throw new Exception(
                "'certificate' and/or 'privatekey' parameters not defined in eIDAS hosted IdP Metadata."
            );
        }

        $hikeypem = Tools::readCertKeyFile($hiKeyPath);
        $hicertpem = Tools::readCertKeyFile($hiCertPath);

        $IdPdialect = $spMetadata->getString('dialect', $idpMetadata->getString('dialect'));

        $encryptAssertions = $spMetadata->getBoolean(
            'assertion.encryption',
            $idpMetadata->getBoolean('assertion.encryption', false)
        );
        Logger::debug('Encrypt assertions: ' . $encryptAssertions);

        $encryptAlgorithm = $spMetadata->getString(
            'assertion.encryption.keyAlgorithm',
            $idpMetadata->getString('assertion.encryption.keyAlgorithm', SPlib::AES256_CBC)
        );
        $storkize = $spMetadata->getBoolean(
            'assertion.storkize',
            $idpMetadata->getBoolean('assertion.storkize', false)
        );

        //Hybrid STORK-eIDAS-own brew behaviour to get the ACS  // TODO: should we keep it like this? or maybe turn it around? (if fixed, use it, otherwise, use request value)?

        $acs = '';
        if (array_key_exists('assertionConsumerService', $reqData)) {
            $acs = $reqData['assertionConsumerService'];
        }
        //If none, get it from the remote SP metadata
        if ($acs === null || $acs === '') {
            $acs = $spMetadata->getArray('AssertionConsumerService', [[
                'Location' => '',
            ]])[0]['Location'];
        }

        if ($acs === null || $acs === '') {
            throw new Exception(
                "Assertion Consumer Service URL not found on the request nor metadata for the entity: ${spEntityId}."
            );
        }

        $metadataUrl = Module::getModuleURL('clave/idp/metadata.php');

        $forwardedParams = [];
        if (isset($state['idp:postParams'])) {
            $forwardedParams = $state['idp:postParams'];
        }

        $storkResp = new SPlib();

        if ($IdPdialect === 'eidas') {
            $storkResp->setEidasMode();
        }

        $storkResp->setSignatureKeyParams($hicertpem, $hikeypem, SPlib::RSA_SHA256);

        $storkResp->setSignatureParams(SPlib::SHA256, SPlib::EXC_C14N);

        if ($encryptAssertions === true) {
            $storkResp->setCipherParams($reqData['spCert'], $encryptAssertions, $encryptAlgorithm);
        }

        $storkResp->setResponseParameters(
            $storkResp::CNS_OBT,
            $acs,
            $reqData['id'],
            $idpMetadata->getString('issuer', $metadataUrl)
        );

        if ($structassertions !== null) {
            $assertions = self::buildStructAssertions($structassertions, $storkResp, $state);
        } elseif ($rawassertions !== null) {
            $assertions = $rawassertions;
        } else {
            $assertions = self::buildStandardAssertions(
                $idpMetadata,
                $metadataUrl,
                $singleassertion,
                $storkResp,
                $state
            );
        }

        if (isset($state['eidas:raw:status'])) {
            $status = $state['eidas:raw:status'];
        } elseif (isset($state['eidas:status'])) {
            $status = $storkResp->generateStatus([
                'MainStatusCode' => $state['eidas:status']['MainStatusCode'],
                'SecondaryStatusCode' => $state['eidas:status']['SecondaryStatusCode'],
                'StatusMessage' => $state['eidas:status']['StatusMessage'],
            ]);
        } else {
            $status = $storkResp->generateStatus([
                'MainStatusCode' => SPlib::ST_SUCCESS,
            ]);
        }

        $resp = $storkResp->generateStorkResponse($status, $assertions, true, true, $storkize);
        Logger::debug('Response to send to the remote SP: ' . $resp);

        $status = [
            'Code' => $state['eidas:status']['MainStatusCode'],
            'SubCode' => $state['eidas:status']['SecondaryStatusCode'],
            'Message' => $state['eidas:status']['StatusMessage'],
        ];
        $statsData = [
            'spEntityID' => $spEntityId,
            'idpEntityID' => $idpMetadata->getString('issuer', $metadataUrl),
            'protocol' => 'saml2-' . $IdPdialect,
            'status' => $status,
        ];
        if (isset($state['saml:AuthnRequestReceivedAt'])) {
            $statsData['logintime'] = microtime(true) - $state['saml:AuthnRequestReceivedAt'];
        }
        Stats::log('clave:idp:Response', $statsData);

        $post = [
            'SAMLResponse' => base64_encode($resp),
        ] + $forwardedParams;

        if ($relayState !== null) {
            $post['RelayState'] = $relayState;
        }

        HTTP::submitPOSTData($acs, $post);
    }

    /**
     * Handle authentication error.
     *
     * SimpleSAML\Error\Exception $exception  The exception.
     *
     * @param array $state The error state.
     * @throws Exception
     */
    public static function handleAuthError(Exception $exception, array $state)
    {
        if (! isset($state['SPMetadata'])) {
            Logger::error('Missing $state["SPMetadata"]');
        }
        if (! isset($state['saml:ConsumerURL'])) {
            Logger::error('Missing $state["saml:ConsumerURL"]');
        }
        if (! array_key_exists('saml:RequestId', $state)) {
            Logger::error('saml:RequestId key missing in $state array');
        }
        if (! array_key_exists('saml:RelayState', $state)) {
            Logger::error('saml:RelayState key missing in $state array');
        }

        $spMetadata = Configuration::loadFromArray($state['SPMetadata']);
        $spEntityId = $spMetadata->getString('entityid', null);
        Logger::debug('eIDAS SP remote metadata (' . $spEntityId . '): ' . print_r($spMetadata, true));

        Logger::debug('Sending eIDAS Response to ' . var_export($spEntityId, true));

        $relayState = null;
        if (isset($state['saml:RelayState'])) {
            $relayState = $state['saml:RelayState'];
        }

        $requestId = $state['saml:RequestId'];
        $consumerURL = $state['saml:ConsumerURL'];
        $protocolBinding = $state['saml:Binding'];

        $idp = IdP::getByState($state);

        $idpMetadata = $idp->getConfig();

        $error = Error::fromException($exception);

        Logger::warning("Returning error to SP with entity ID '" . var_export($spEntityId, true) . "'.");
        $exception->log(Logger::WARNING);

        $ar = self::buildResponse($idpMetadata, $spMetadata, $consumerURL);
        $ar->setInResponseTo($requestId);
        $ar->setRelayState($relayState);

        $status = [
            'Code' => $error->getStatus(),
            'SubCode' => $error->getSubStatus(),
            'Message' => $error->getStatusMessage(),
        ];
        $ar->setStatus($status);

        $statsData = [
            'spEntityID' => $spEntityId,
            'idpEntityID' => $idpMetadata->getString('entityID'),
            'protocol' => 'saml2',
            'error' => $status,
        ];
        if (isset($state['saml:AuthnRequestReceivedAt'])) {
            $statsData['logintime'] = microtime(true) - $state['saml:AuthnRequestReceivedAt'];
        }
        Stats::log('saml:idp:Response:error', $statsData);

        $binding = Binding::getBinding($protocolBinding);
        $binding->send($ar);
    }

    /**
     * Build the assertions, based on the existing variables (generate the xml and pass it as it were raw): if struct,
     * we prefer struct, but if only one assertion, use standard, if >1 use struct
     */
    private static function buildStructAssertions($structAssertions, $storkResp, $state): array
    {
        $assertions = [];
        foreach ($structAssertions as $assertionData) {

            // TODO: This block is legacy. Should be implemented on the esmo
            //   module authsource acs and removed from here. It is already
            //   implemented on this acs
            if (isset($state['saml:sp:NameID'])) {
                $assertionData['NameID'] = $state['saml:sp:NameID'];
            } else {
                //Set the NameID from the eIDAS ID attribute
                //$idAttrName = 'eIdentifier';
                //TODO: is this mandatory in STORK? fro the moment, leave it out
                // maybe define a param to mark the ID attr line in AdAS?
                $idAttrName = 'PersonIdentifier';
                foreach ($assertionData['attributes'] as $attr) {
                    if ($attr['friendlyName'] === $idAttrName
                        || $attr['name'] === $idAttrName) {
                        $assertionData['NameID'] = $attr['values'][0];
                        break;
                    }
                }
            }
            if (! isset($assertionData['NameIDFormat'])) {
                $assertionData['NameIDFormat'] = SPlib::NAMEID_FORMAT_PERSISTENT;
            }
            $assertions[] = $storkResp->generateAssertion($assertionData);
        }
        return $assertions;
    }

    /**
     * This method was called from a standard AuthSource and only has the standard attribute list
     */
    private static function buildStandardAssertions(
        $idpMetadata,
        $metadataUrl,
        $singleassertion,
        $storkResp,
        $state
    ): array {
        $assertionData = [];
        $assertionData['Issuer'] = $idpMetadata->getString('issuer', $metadataUrl);

        $assertionData['attributes'] = [];
        foreach ($singleassertion as $attributename => $values) {
            $attributefullname = $attributename;
            if (isset($state['eidas:attr:names'])) {
                if (isset($state['eidas:attr:names'][$attributename])) {
                    $attributefullname = $state['eidas:attr:names'][$attributename];
                }
            }

            $assertionData['attributes'][] = [
                'values' => $values,
                'friendlyName' => $attributename,
                'name' => $attributefullname,
            ];
        }

        if (isset($state['saml:sp:NameID'])) {
            $assertionData['NameID'] = $state['saml:sp:NameID'];
        } else {
            //Set the NameID from the eIDAS ID attribute
            //$idAttrName = 'eIdentifier';
            //TODO: is this mandatory in STORK? fro the moment, leave it out
            $idAttrName = 'PersonIdentifier';
            foreach ($assertionData['attributes'] as $attr) {
                if ($attr['friendlyName'] === $idAttrName
                    || $attr['name'] === $idAttrName) {
                    $assertionData['NameID'] = $attr['values'][0];
                    break;
                }
            }
        }
        $assertionData['NameIDFormat'] = SPlib::NAMEID_FORMAT_PERSISTENT;

        if (isset($state['saml:AuthnContextClassRef'])) {
            $assertionData['AuthnContextClassRef'] = $state['saml:AuthnContextClassRef'];
        }

        return [$storkResp->generateAssertion($assertionData)];
    }

    /**
     * Build a authentication response based on information in the metadata.
     *
     * @param Configuration $idpMetadata The metadata of the IdP.
     * @param Configuration $spMetadata The metadata of the SP.
     * @param string $consumerURL The Destination URL of the response.
     *
     * @return Response The SAML2 response corresponding to the given data.
     * @throws Exception
     */
    private static function buildResponse(
        Configuration $idpMetadata,
        Configuration $spMetadata,
        string $consumerURL
    ): Response {
        $signResponse = $spMetadata->getBoolean('saml20.sign.response', null);
        if ($signResponse === null) {
            $signResponse = $idpMetadata->getBoolean('saml20.sign.response', true);
        }

        $r = new Response();

        $r->setIssuer(
            $idpMetadata->getString('entityID')
        );  // TODO: you may need to change this so that the one in the original answer is returned. Or make it dialect-specific. To decide
        $r->setDestination($consumerURL);

        if ($signResponse) {
            Message::addSign($idpMetadata, $spMetadata, $r);
        }

        return $r;
    }
}
