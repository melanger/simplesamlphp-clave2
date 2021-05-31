<?php

namespace SimpleSAML\Module\clave;

use SimpleSAML\Configuration;
use SimpleSAML\Error\Exception;
use SimpleSAML\Error\MetadataNotFound;
use SimpleSAML\Metadata\MetaDataStorageHandler;
use SimpleSAML\Utils\Config;

class Tools
{
    /**
     * Loads a metadata set from the clave specific metadata files. Metadata directory is taken from the global
     * configuration
     *
     * The Id of the entoty whose metadata we want
     *
     * Don't use _once in metadataFile or the global variable might get unset.
     *
     * @param $entityId
     * which metadada set to read from (the name of the file without extension)
     * @param $set
     * metadata for the entity
     * @throws Exception
     */
    public static function getMetadataSet($entityId, $set): Configuration
    {
        $globalConfig = Configuration::getInstance();
        $metadataDirectory = $globalConfig->getString('metadatadir', 'metadata/');
        $metadataDirectory = $globalConfig->resolvePath($metadataDirectory) . '/';

        $metadataFile = $metadataDirectory . '/' . $set . '.php';
        try {
            require($metadataFile);
        } catch (Exception $e) {
            throw new Exception('Clave Metadata file ' . $metadataFile . ' not found.');
        }

        if (! isset($claveMeta)) {
            throw new Exception(
                'Clave Metadata set ' . $set . ': malformed or undefined global clave metadata variable'
            );
        }

        if (! isset($claveMeta[$entityId])) {
            throw new Exception('Entity ' . $entityId . ' not found in set ' . $set);
        }

        return Configuration::loadFromArray($claveMeta[$entityId]);
    }

    /**
     * Retrieves metadata for a given clave SP, but taking into account whether he must search the clave or the saml20
     * metadatafiles.
     *
     * @param $spEntityId
     * @throws MetadataNotFound
     * @throws Exception
     */
    public static function getSPMetadata(Configuration $claveConfig, $spEntityId): ?Configuration
    {
        if (! $claveConfig->getBoolean('sp.useSaml20Meta', false)) {
            $spMetadata = self::getMetadataSet($spEntityId, 'clave-sp-remote');
        } else {
            $metadata = MetaDataStorageHandler::getMetadataHandler();
            $spMetadata = $metadata->getMetaDataConfig($spEntityId, 'saml20-sp-remote');
        }

        return $spMetadata;
    }

    /**
     * Reads file relative to the configured cert directory
     *
     * @throws Exception
     */
    public static function readCertKeyFile(string $relativePath): string
    {
        if ($relativePath === null || $relativePath === '') {
            throw new Exception('Unable to load cert or key from file: path is empty');
        }

        $path = Config::getCertPath($relativePath);
        $data = @file_get_contents($path);
        if ($data === false) {
            throw new Exception('Unable to load cert or key from file "' . $path . '"');
        }

        return $data;
    }

    /**
     * Lists of clave paraeters are sent as ; separated field strings
     *
     * @param $idpArray
     * @return false|string
     */
    public static function serializeIdpList($idpArray)
    {
        if (count($idpArray) <= 0) {
            return '';
        }

        $idpList = '';
        foreach ($idpArray as $idp) {
            $idpList .= $idp . ';';
        }
        return substr($idpList, 0, strlen($idpList) - 1);
    }

    /**
     * @throws Exception
     */
    public static function findX509SignCertOnMetadata(Configuration $metadata): array
    {
        $ret = [];

        $keys = $metadata->getArray('keys', null);
        if ($keys === null) {
            throw new Exception('No key entry found in metadata: ' . print_r($metadata, true));
        }

        foreach ($keys as $key) {
            if ($key['type'] !== 'X509Certificate') {
                continue;
            }
            if (! $key['signing']) {
                continue;
            }
            if (! $key['X509Certificate'] || $key['X509Certificate'] === '') {
                continue;
            }

            $ret[] = $key['X509Certificate'];
        }

        if (sizeof($ret) <= 0) {
            throw new Exception('No X509 signing certificate found in metadata: ' . print_r($metadata, true));
        }

        return $ret;
    }
}
