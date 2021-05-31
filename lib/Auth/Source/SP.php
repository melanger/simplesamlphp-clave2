<?php

namespace SimpleSAML\Module\clave;

use SimpleSAML\Auth\ProcessingChain;
use SimpleSAML\Auth\Source;
use SimpleSAML\Auth\State;
use SimpleSAML\Configuration;
use SimpleSaml\Error\Exception;
use SimpleSAML\Logger;
use SimpleSAML\Module;
use SimpleSAML\Stats;
use SimpleSAML\Utils\HTTP;

/**
 * @method static handleUnsolicitedAuth($sourceId, $state, $redirectTo)
 */
class Auth_Source_SP extends Source
{
    private static $mandatoryConfigParams = ['providerName', 'entityid', 'QAA',
        'certificate', 'privatekey', 'idpEntityID', 'SingleSignOnService', 'certData',
        'hostedSP', 'dialect', 'subdialect', ];

    /**
     * The entity ID of this SP.
     *
     * @var string
     */
    private $entityId;

    /**
     * The metadata of this SP (the authSource cofngi file entry content).
     *
     * @var Configuration.
     */
    private $metadata;

    /**
     * The entityID of the remote IdP we will be contacting.
     *
     * @var string  The IdP the user will log into.
     */
    private $idp;

    /**
     * URL to discovery service.
     *
     * @var string|null
     */
    private $discoURL;

    /**
     * The metadata of the hosted SP configured in the authSource.
     *
     * @var Configuration.
     */
    private $spMetadata;

    /**
     * The metadata of the remote IdP.
     *
     * @var Configuration.
     */
    private $idpMetadata;

    /**
     * The Dialect this SP will use to contact the remote IdP
     *
     * @var string Dialect identifier.
     */
    private $dialect;

    /**
     * The Sub-Dialect this SP will use to contact the remote IdP
     *
     * @var string Sub-Dialect identifier.
     */
    private $subdialect;

    /**
     * The Certificate that will be used to sign the AuthnReq.
     *
     * @var string PEM encoded without headers.
     */
    private $certData;

    /**
     * The Private Key that will be used to sign the AuthnReq.
     *
     * @var string PEM encoded without headers.
     */
    private $keyData;

    /**
     * Constructor for SAML2-eIDAS SP authentication source.
     *
     * @param array $info Information about this authentication source (contains AuthId, the id of this auth source).
     * @param array $config Configuration block of this authsource in authsources.php.
     * @throws Exception
     */
    public function __construct($info, $config)
    {
        if (! is_array($info)) {
            Logger::error('$info is not array');
        }

        if (! is_array($config)) {
            Logger::error('$config is not array');
        }

        parent::__construct($info, $config);

        Logger::debug('Called Auth_Source_SP constructor');
        Logger::debug('config: ' . print_r($config, true));

        $this->metadata = Configuration::loadFromArray(
            $config,
            'authsources[' . var_export($this->authId, true) . ']'
        );

        $spConfId = $this->metadata->getString('hostedSP', null);
        if ($spConfId === null) {
            throw new Exception('hostedSP field not defined for eIDAS auth source.');
        }
        $this->spMetadata = Tools::getMetadataSet($spConfId, 'clave-sp-hosted');
        Logger::debug('eIDAS SP hosted metadata: ' . print_r($this->spMetadata, true));

        //Get the remote idp metadata
        $idpEntityId = $this->spMetadata->getString('idpEntityID', null);
        if ($idpEntityId === null) {
            throw new Exception('idpEntityID field not defined for eIDAS auth source.');
        }
        $this->idpMetadata = Tools::getMetadataSet($idpEntityId, 'clave-idp-remote');
        Logger::debug('eIDAS IDP remote metadata (' . $idpEntityId . '): ' . print_r($this->idpMetadata, true));

        //TODO Check if all mandatory config is available (in any of the sets),
        // review this, as there might be collisions, and review the list of mandatory
        foreach (self::$mandatoryConfigParams as $mandParam) {
            $value = $this->metadata->getValue($mandParam);
            if ($value === null) {
                $value = $this->spMetadata->getValue($mandParam);
            }
            if ($value === null) {
                $value = $this->idpMetadata->getValue($mandParam);
            }
            if ($value === null) {
                throw new Exception("${mandParam} field not defined for eIDAS auth source.");
            }
        }

        $this->discoURL = $this->metadata->getString(
            'discoURL',
            'clave/sp/countryselector.php'
        ); // TODO: default value. can be moved elsewhere? can module name be parametrised? anyway, remember to change module name
        $this->entityId = $this->spMetadata->getString('entityid');
        $this->idp = $idpEntityId;
        $this->dialect = $this->spMetadata->getString('dialect');
        $this->subdialect = $this->spMetadata->getString('subdialect');

        $this->certData = Tools::readCertKeyFile($this->spMetadata->getString('certificate', null));
        $this->keyData = Tools::readCertKeyFile($this->spMetadata->getString('privatekey', null));

        // TODO: to delete as ssphp impl has changed. seek if this data needs to be passed elsewhere
        //      $this->idp = array('endpoint' => $this->idpMetadata->getString('SingleSignOnService', NULL),
        //                   'cert'     => $this->idpMetadata->getString('certData', NULL));
    }

    /**
     * Retrieve the URL to the metadata of this SP (eIDAS).
     *
     * @return string  The metadata URL.
     * @throws Exception
     */
    public function getMetadataURL(): string
    {
        $spConfId = $this->metadata->getString('hostedSP', null);
        return Module::getModuleURL(
            'clave/sp/metadata.php/' . 'clave/' . urlencode($spConfId) . '/' . urlencode($this->authId)
        );
    }

    /**
     * Retrieve the entity id of this SP.
     *
     * @return string  The entity id of this SP.
     */
    public function getEntityId(): string
    {
        return $this->entityId;
    }

    /**
     * Retrieve the metadata of this SP (the authSource content).
     *
     * @return Configuration  The metadata of this SP.
     */
    public function getMetadata(): Configuration
    {
        return $this->metadata;
    }

    /**
     * Retrieve the metadata of an IdP, eIDEAS doesn't support the list of allowed IDPs.
     *
     * @param string $entityId  The entity id of the IdP.
     * @return Configuration  The metadata of the IdP.
     */
    public function getIdPMetadata(string $entityId = ''): Configuration
    {
        if (! is_string($entityId)) {
            Logger::error('$entityId is not string');
        }
        return $this->idpMetadata;
    }

    /**
     * Start login.
     *
     * This function saves the information about the login, and redirects to the IdP.
     *
     * @param array $state Information about the current authentication.
     * @throws Exception
     */
    public function authenticate(&$state)
    {
        if (! is_array($state)) {
            Logger::error('$state is not array');
        }

        Logger::debug('------------------STATE at SP.authenticate (start): ' . print_r($state, true));

        Logger::debug('Called Auth_Source_SP authenticate');

        $state['clave:sp:AuthId'] = $this->authId;

        if (isset($state['saml:idp'])
        && $state['saml:idp'] !== '') {
            $idpEntityId = $state['saml:idp'];

            Logger::debug('eIDAS IDP remote fixed by hosted IDP: (' . $idpEntityId . ')');
            $this->idp = $idpEntityId;

            $this->idpMetadata = Tools::getMetadataSet($idpEntityId, 'clave-idp-remote');
            Logger::debug('eIDAS IDP remote metadata (' . $idpEntityId . '): ' . print_r($this->idpMetadata, true));
        }

        $state['clave:sp:idpEntityID'] = $this->idp;

        Logger::debug('state: ' . print_r($state, true));
        Logger::debug('metadata: ' . print_r($this->metadata, true));

        $this->startDisco($state);

        Logger::debug('------------------STATE at SP.authenticate (end): ' . print_r($state, true));

        $this->startSSO($this->idp, $state);
    }

    /**
     * Send a SSO request to an IdP.
     *
     * @param string $idp The entity ID of the IdP.
     * @param array $state The state array for the current authentication.
     * @throws Exception
     */
    public function startSSO(string $idp, array $state)
    {
        if (! is_string($idp)) {
            Logger::error('$idp is not string');
        }

        Logger::debug('------------------STATE at SP.authenticate (end): ' . print_r($state, true));

        Logger::debug('Called Auth_Source_SP startSSO');

        $remoteSpMeta = Configuration::loadFromArray($state['SPMetadata']);

        $showCountrySelector = $this->spMetadata->getBoolean('showCountrySelector', false);

        $endpoint = $this->idpMetadata->getString('SingleSignOnService', null);

        $sectorShare = '';
        $crossSectorShare = '';
        $crossBorderShare = '';
        $LoA = 1;
        if ($this->dialect === 'stork') {
            $SPCountry = $remoteSpMeta->getString(
                'spCountry',
                $this->spMetadata->getString('spCountry', '' . $state['eidas:requestData']['spCountry'])
            );
            $SPsector = $remoteSpMeta->getString(
                'spSector',
                $this->spMetadata->getString('spSector', '' . $state['eidas:requestData']['spSector'])
            );
            $SPinstitution = $remoteSpMeta->getString(
                'spInstitution',
                $this->spMetadata->getString('spInstitution', '' . $state['eidas:requestData']['spInstitution'])
            );
            $SPapp = $remoteSpMeta->getString(
                'spApplication',
                $this->spMetadata->getString('spApplication', '' . $state['eidas:requestData']['spApplication'])
            );
            $SpId = $remoteSpMeta->getString(
                'spID',
                $this->spMetadata->getString('spID', '' . $state['eidas:requestData']['spID'])
            );
            $sectorShare = $remoteSpMeta->getBoolean('eIDSectorShare', $this->spMetadata->getBoolean(
                'eIDSectorShare',
                SPlib::stb($state['eidas:requestData']['eIDSectorShare'])
            ));
            $crossSectorShare = $remoteSpMeta->getBoolean('eIDCrossSectorShare', $this->spMetadata->getBoolean(
                'eIDCrossSectorShare',
                SPlib::stb($state['eidas:requestData']['eIDCrossSectorShare'])
            ));
            $crossBorderShare = $remoteSpMeta->getBoolean('eIDCrossBorderShare', $this->spMetadata->getBoolean(
                'eIDCrossBorderShare',
                SPlib::stb($state['eidas:requestData']['eIDCrossBorderShare'])
            ));

            $CitizenCountry = '';
            if ($this->subdialect === 'clave-1.0') {
                $CitizenCountry = $remoteSpMeta->getString(
                    'citizenCountryCode',
                    $this->spMetadata->getString(
                        'citizenCountryCode',
                        '' . $state['eidas:requestData']['citizenCountryCode']
                    )
                );
            }
            if ($this->subdialect === 'stork') {
                if ($showCountrySelector === true) {
                    $CitizenCountry = $state['country'];
                }
            }

            $reqIssuer = $this->getIssuer($state, $remoteSpMeta);

            if (! array_key_exists('QAA', $state['eidas:requestData'])
            || $state['eidas:requestData']['QAA'] === null
            || $state['eidas:requestData']['QAA'] === '') {
                $state['eidas:requestData']['QAA'] = 1;
            }
            $QAA = $this->spMetadata->getInteger(
                'QAA',
                $remoteSpMeta->getInteger('QAA', $state['eidas:requestData']['QAA'])
            );
            $LoA = SPlib::qaaToLoA($QAA);
        }

        if ($this->dialect === 'eidas') {
            if (! array_key_exists('IdFormat', $state['eidas:requestData'])
            || $state['eidas:requestData']['IdFormat'] === null
            || $state['eidas:requestData']['IdFormat'] === '') {
                $state['eidas:requestData']['IdFormat'] = SPlib::NAMEID_FORMAT_PERSISTENT;
            }

            if (! array_key_exists('SPType', $state['eidas:requestData'])
            || $state['eidas:requestData']['SPType'] === null
            || $state['eidas:requestData']['SPType'] === '') {
                $state['eidas:requestData']['SPType'] = SPlib::EIDAS_SPTYPE_PUBLIC;
            }

            if (! array_key_exists('LoA', $state['eidas:requestData'])
            || $state['eidas:requestData']['LoA'] === null
            || $state['eidas:requestData']['LoA'] === '') {
                $state['eidas:requestData']['LoA'] = SPlib::qaaToLoA($state['eidas:requestData']['QAA']);
            }

            $SPType = $this->spMetadata->getString(
                'SPType',
                $remoteSpMeta->getString('SPType', $state['eidas:requestData']['SPType'])
            );
            $NameIDFormat = $this->spMetadata->getString(
                'NameIDFormat',
                $remoteSpMeta->getString('NameIDFormat', $state['eidas:requestData']['IdFormat'])
            );

            if (isset($state['eidas:requestData']['LoA'])
                && $state['eidas:requestData']['LoA'] !== '') {
                Logger::debug('Setting LoA from request: ' . $state['eidas:requestData']['LoA']);
                $LoA = $state['eidas:requestData']['LoA'];
            } else {
                $LoA = $this->spMetadata->getString('LoA', $remoteSpMeta->getString('LoA', SPlib::LOA_LOW));
                Logger::debug('Setting LoA from Metadata: ' . $LoA);
            }
            $QAA = SPlib::loaToQaa($LoA);
            $state['eidas:requestData']['QAA'] = SPlib::loaToQaa($LoA);

            $CitizenCountry = '';
            if ($showCountrySelector === true) {
                $CitizenCountry = $state['country'];
            }

            $metadataURL = $this->getMetadataURL();

            $reqIssuer = $metadataURL;
        }

        $providerName = $this->spMetadata->getString('providerName', null);
        $providerName = $this->getCompleteProviderName($providerName, $remoteSpMeta);

        $returnPage = Module::getModuleURL('clave/sp/clave-acs.php/' . $this->authId);

        $eidas = new SPlib();
        Logger::debug('******************************+LoA: ' . $LoA);
        if ($this->dialect === 'eidas') {
            $eidas->setEidasMode();
            $eidas->setEidasRequestParams($SPType, $NameIDFormat, $LoA);
        }

        $eidas->forceAuthn();

        $eidas->setSignatureKeyParams($this->certData, $this->keyData, SPlib::RSA_SHA512);
        $eidas->setSignatureParams(SPlib::SHA512, SPlib::EXC_C14N);

        $eidas->setServiceProviderParams($providerName, $reqIssuer, $returnPage);

        if ($this->dialect === 'stork') {
            $eidas->setSPLocationParams($SPCountry, $SPsector, $SPinstitution, $SPapp);
            $eidas->setSPVidpParams($SpId, $CitizenCountry);
        }

        $eidas->setSTORKParams($endpoint, $QAA, $sectorShare, $crossSectorShare, $crossBorderShare);

        $mandatory = [];
        $attributes = [];

        $this->checkRelayStateAttribute($state, $attributes);

        if (array_key_exists('requestedAttributes', $state['eidas:requestData'])
        && is_array($state['eidas:requestData']['requestedAttributes'])
        ) {
            foreach ($state['eidas:requestData']['requestedAttributes'] as $attr) {
                if ($this->dialect === 'stork') {
                    $name = SPlib::getFriendlyName($attr['name']);
                }
                if ($this->dialect === 'eidas') {
                    if (array_key_exists('friendlyName', $attr)) {
                        $name = $attr['friendlyName'];
                    } else {
                        $name = SPlib::getEidasFriendlyName($attr['name']);
                        if ($name === '') {
                            $name = $attr['name'];
                        }
                    }
                }
                $attributes[] = [$name, $attr['isRequired'], $attr['values']];  // TODO: add the values array here

                if (SPlib::stb($attr['isRequired']) === true) {
                    $mandatory[] = $name;
                }
            }
        } else {
            $attrsToRequest = $state['SPMetadata']['attributes'];

            if ($attrsToRequest === null || count($attrsToRequest) <= 0) {
                if ($this->dialect === 'stork') {
                    $attrsToRequest = ['eIdentifier', 'givenName', 'surname'];
                }
                if ($this->dialect === 'eidas') {
                    $attrsToRequest = ['PersonIdentifier', 'FirstName', 'FamilyName', 'DateOfBirth'];
                }
            }

            foreach ($attrsToRequest as $attr) {
                $mandatory = false;

                if ($this->dialect === 'eidas') {
                    if (in_array($attr, ['PersonIdentifier', 'FirstName', 'FamilyName', 'DateOfBirth'], true)) {
                        $mandatory = true;
                        $mandatory[] = $attr;
                    }
                }
                $attributes[] = [$attr, $mandatory];
            }
        }

        foreach ($attributes as $attribute) {
            $values = null;

            if (isset($attribute[2])
            && is_array($attribute[2])
            && sizeof($attribute[2]) > 0) {
                $values = $attribute[2];
            }

            $eidas->addRequestAttribute($attribute[0], $attribute[1], $values);
        }

        // TODO Seguir
        if (isset($state['saml:RelayState'])) {
            $holdRelayState = $this->spMetadata->getBoolean(
                'holdRelayState',
                $remoteSpMeta->getBoolean('holdRelayState', false)
            );
            Logger::debug('------------------------hold relay state?: ' . $holdRelayState);

            if ($holdRelayState) {
                $state['saml:HeldRelayState'] = $state['saml:RelayState'];
                $state['saml:RelayState'] = 'RS_held_at_Bridge';
                Logger::debug('------------------------curr value: ' . $state['saml:RelayState']);
                Logger::debug('------------------------held value: ' . $state['saml:HeldRelayState']);
            }
        }

        $state['clave:sp:returnPage'] = $returnPage;
        $state['clave:sp:mandatoryAttrs'] = $mandatory;
        $id = State::saveState($state, 'clave:sp:req', true);
        Logger::debug('Generated Req ID: ' . $id);

        $eidas->setRequestId($id);

        $req = base64_encode($eidas->generateStorkAuthRequest());
        Logger::debug('Auth_Source_SP Generated AuthnReq: ' . $req);

        Stats::log('clave:sp:AuthnRequest', [
            'spEntityID' => $this->entityId,
            // TODO: put the entityId or the issuer?
            'idpEntityID' => $this->idp,
            'forceAuthn' => true,
            'isPassive' => false,
            'protocol' => 'saml2-' . $this->dialect,
            'idpInit' => false,
        ]);

        $this->redirect($endpoint, $req, $state);
    }

    /**
     * Handle a response from a SSO operation.
     *
     * @param array $state The authentication state.
     * @param string $idp The entity id of the remote IdP.
     * @param array $attributes The attributes.
     * @throws Exception
     * @throws UnserializableException
     * @throws Exception
     */
    public function handleResponse(array $state, string $idp, array $attributes)
    {
        if (! is_string($idp)) {
            Logger::error('$idp is not string');
        }

        $idpMetadata = $this->getIdpMetadata($idp);

        $spMetadataArray = $this->metadata->toArray();
        $idpMetadataArray = $idpMetadata->toArray();

        $state['saml:sp:IdP'] = $idp;
        $state['PersistentAuthData'][] = 'saml:sp:IdP';

        $authProcState = [
            'saml:sp:IdP' => $idp,
            'saml:sp:State' => $state,
            'ReturnCall' => ['Auth_Source_SP', 'onProcessingCompleted'],

            'Attributes' => $attributes,
            'Destination' => $spMetadataArray,
            'Source' => $idpMetadataArray,
        ];

        if (isset($state['saml:sp:NameID'])) {
            $authProcState['saml:sp:NameID'] = $state['saml:sp:NameID'];
        }
        if (isset($state['saml:sp:SessionIndex'])) {
            $authProcState['saml:sp:SessionIndex'] = $state['saml:sp:SessionIndex'];
        }
        $pc = new ProcessingChain($idpMetadataArray, $spMetadataArray, 'sp');
        $pc->processState($authProcState);

        self::onProcessingCompleted($authProcState);
    }

    /**
     * Called when we have completed the processing chain.
     *
     * @param array $authProcState The processing chain state.
     * @throws Exception
     * @throws Exception
     */
    public static function onProcessingCompleted(array $authProcState)
    {
        if (! array_key_exists('saml:sp:IdP', $authProcState)) {
            Logger::error('saml:sp:IdP key missing in $authProcState array');
        }
        if (! array_key_exists('saml:sp:State', $authProcState)) {
            Logger::error('saml:sp:State key missing in $authProcState array');
        }
        if (! array_key_exists('Attributes', $authProcState)) {
            Logger::error('Attributes key missing in $authProcState array');
        }

        $state = $authProcState['saml:sp:State'];

        $sourceId = $state['clave:sp:AuthId'];
        $source = Source::getById($sourceId);
        if ($source === null) {
            throw new Exception('Could not find authentication source with id ' . $sourceId);
        }

        //TODO: Register a callback that we can call if we receive a logout request from the IdP. Review when implementing SLO
        // $source->addLogoutCallback($idp, $state);
        $state['Attributes'] = $authProcState['Attributes'];

        if (isset($state['saml:sp:isUnsolicited']) && $state['saml:sp:isUnsolicited']) {
            if (! empty($state['saml:sp:RelayState'])) {
                $redirectTo = $state['saml:sp:RelayState'];
            } else {
                $redirectTo = $source->getMetadata()
                    ->getString('RelayState', '/');
            }
            self::handleUnsolicitedAuth($sourceId, $state, $redirectTo);
        }

        Source::completeAuth($state);
    }

    // TODO: review and merge/refactor all the logout part. Not now. At the end, as it only is useful for clave1 (maybe in the future for clave2).

    /**
     * Start logout operation.
     *
     * @param array $state The logout state.
     * @throws Exception
     * @throws Exception
     */
    public function logout(&$state)
    {
        if (! is_array($state)) {
            Logger::error('$state is not array');
        }

        $this->startSLO2($state);
    }

    /**
     * Start a SAML 2 logout operation.
     *
     * @param array $state The logout state.
     * @throws Exception
     */
    public function startSLO2(array &$state)
    {
        if (! is_array($state)) {
            Logger::error('$state is not array');
        }

        $providerName = $this->spMetadata->getString('providerName', null);

        $endpoint = $this->idpMetadata->getString('SingleLogoutService', null);
        if ($endpoint === null) {
            Logger::debug('No logout endpoint for clave remote IdP.');
            return;
        }

        $returnPage = Module::getModuleURL('clave/sp/logout-return.php/' . $this->authId);

        $eidas = new SPlib();

        $eidas->setSignatureKeyParams($this->certData, $this->keyData, SPlib::RSA_SHA512);
        $eidas->setSignatureParams(SPlib::SHA512, SPlib::EXC_C14N);

        $state['clave:sp:slo:returnPage'] = $returnPage;
        $id = State::saveState($state, 'clave:sp:slo:req', true);
        Logger::debug('Generated Req ID: ' . $id);

        $req = base64_encode($eidas->generateSLORequest($providerName, $endpoint, $returnPage, $id));
        Logger::debug('Generated LogoutRequest: ' . $req);

        $post = [
            'samlRequestLogout' => $req,
            'RelayState' => 'dummy',
        ];

        HTTP::submitPOSTData($endpoint, $post);
    }

    /**
     * Issuer is returned in this order 0. If the UseMetadataUrl is set, use hosted SP metadata URL 1. Hosted SP
     * metadata issuer field (if set) 2. Remote SP metadata issuer field (if set) 3. Issuer Field specified on the
     * remote SP request (Dropped using the entityId of the hosted SP)
     *
     * @param $remoteSpMeta
     * @return mixed|string
     * @throws Exception
     */
    private function getIssuer(array $state, $remoteSpMeta)
    {
        $useMetadataUrl = $this->spMetadata->getBoolean('useMetadataUrl', false);
        if (! $useMetadataUrl) {
            return $this->spMetadata->getString(
                'issuer',
                $remoteSpMeta->getString('issuer', $state['eidas:requestData']['issuer'])
            );
        }
        return $this->getMetadataURL();
    }

    /**
     * Returns complete provider name Provider name has two parts: the first one is the friendlyname of the certificate
     * to validate this request, the second part, the providerName of the remote SP we are proxying, for statistics (we
     * get it from spApplication if set on remote sp metadata, or we get it from the request if available)
     */
    private function getCompleteProviderName($providerName, $remoteSpMeta)
    {
        if ($this->subdialect === 'clave-1.0'
            || $this->subdialect === 'clave-2.0') {
            $remoteProviderName = null;

            if (isset($state['eidas:requestData']['ProviderName'])
                && $state['eidas:requestData']['ProviderName'] !== '') {
                $remoteProviderName = $state['eidas:requestData']['ProviderName'];
            }

            $remoteProviderName = $remoteSpMeta->getString('spApplication', $remoteProviderName);

            $forwardPN = $this->spMetadata->getBoolean('providerName.forward', true);
            if (! $forwardPN) {
                $remoteProviderName = null;
            }

            if ($remoteProviderName !== null) {
                $providerName = $providerName . '_' . $remoteProviderName;
            }
        }
        return $providerName;
    }

    /**
     * Workaround for Clave-2.0. It requires the RelayState attribute to be passed (with its value), but if not passed,
     * it needs to be there anyway (not in the specs, but they implemented them wrong), so we set it as empty.
     */
    private function checkRelayStateAttribute($state, &$attributes)
    {
        if ($this->subdialect === 'clave-2.0') {
            $found = false;
            foreach ($state['eidas:requestData']['requestedAttributes'] as $attr) {
                if ($attr['friendlyName'] === 'RelayState') {
                    $found = true;
                }
            }

            if (! $found) {
                $attributes[] = ['RelayState', false];
            }  // TODO SEGUIR
            // TODO: implement for all eIDAS and STORK to forward the reuqest attr values, if existing
        }
    }

    /**
     * Start a discovery service operation, (country selector in eIDAS).
     *
     * @param array $state The state array.
     * @throws Exception
     */
    private function startDisco(array $state): bool
    {
        Logger::debug('Called Auth_Source_SP startDisco');

        $showCountrySelector = $this->spMetadata->getBoolean('showCountrySelector', false);

        if ($showCountrySelector === false) {
            return true;
        }

        foreach ($state['sp:postParams'] as $postParam => $value) {
            if ($postParam === 'country' && $value !== null
            && is_string($value) && $value !== '') {
                return true;
            }
        }

        $id = Auth\State::saveState($state, 'clave:sp:sso');

        $discoURL = $this->discoURL;
        if (! preg_match('/^\s*https?:/', $this->discoURL)) {
            $discoURL = Module::getModuleURL($this->discoURL);
        }

        $returnTo = Module::getModuleURL('clave/sp/discoresp.php', [
            'AuthID' => $id,
        ]); // TODO: remove clave reference. make the module name a global or something

        $params = [
            // TODO ver si son necesarios y describirlos
            'return' => $returnTo,
        ];

        HTTP::redirectTrustedURL($discoURL, $params);
    }

    /**
     * Do the POST redirection.
     * Will forward authorised POST parameters, if any
     * Some parameters are configurable, but also can be forwarded:
     * - If they came by POST, then that copy is sent to the remote IdP
     * - Else, if they are specifically defined in remote SP metadata, those are sent
     * - Else, if they are specifically defined in tthe authSource metadata, those are sent
     * - Else, not sent
     *
     * @param $destination
     * @param $req
     * @param $state
     * @throws Exception
     * @throws Exception
     */
    private function redirect($destination, $req, $state)
    {
        $remoteSpMeta = Configuration::loadFromArray($state['SPMetadata']);

        $forwardedParams = $state['sp:postParams'];

        //TODO check Add the relay state to the list of forwarded parameters (this way, if the user sent it from the SAML2Int interface, it will work)
        if (isset($state['saml:RelayState'])) {
            $forwardedParams['RelayState'] = $state['saml:RelayState'];
        }

        if ($this->subdialect === 'clave-2.0') {
            $found = false;
            foreach ($forwardedParams as $param => $value) {
                if ($param === 'RelayState') {
                    if ($value === null || $value === '') {
                        $forwardedParams['RelayState'] = 'dummyvalue';
                    }
                    $found = true;
                    break;
                }
            }
            if (! $found) {
                $forwardedParams['RelayState'] = 'dummyvalue';
            }
        }

        $post = [
            'SAMLRequest' => $req,
        ];

        if ($this->subdialect === 'clave-1.0') {
            if (! array_key_exists('idpList', $forwardedParams)) {
                $idpList = $remoteSpMeta->getArray('idpList', $this->spMetadata->getArray('idpList', []));
                if (count($idpList) > 0) {
                    $post['idpList'] = Tools::serializeIdpList($idpList);
                }
            }

            if (! array_key_exists('excludedIdPList', $forwardedParams)) {
                $idpExcludedList = $remoteSpMeta->getArray(
                    'idpExcludedList',
                    $this->spMetadata->getArray('idpExcludedList', [])
                );
                if (count($idpExcludedList) > 0) {
                    $post['excludedIdPList'] = Tools::serializeIdpList($idpExcludedList);
                }
            }

            if (! array_key_exists('forcedIdP', $forwardedParams)) {
                $force = $remoteSpMeta->getString('force', $this->spMetadata->getString('force', null));
                if ($force !== null) {
                    $post['forcedIdP'] = $force;
                }
            }

            if (! array_key_exists('allowLegalPerson', $forwardedParams)) {
                $legal = $remoteSpMeta->getBoolean('allowLegalPerson', false);
                if ($legal === true) {
                    $post['allowLegalPerson'] = 'true';
                }
            }
        }

        // TODO eIDAS
        if ($this->subdialect === 'eidas'
      || $this->subdialect === 'stork') {
            if (! array_key_exists('country', $forwardedParams)) {
                if (isset($state['country'])) {
                    $post['country'] = $state['country'];
                }
            }
        }

        foreach ($forwardedParams as $param => $value) {
            $post[$param] = $value;
        }
        Logger::debug('forwarded: ' . print_r($forwardedParams, true));
        Logger::debug('post: ' . print_r($post, true));

        HTTP::submitPOSTData($destination, $post);
    }
}
