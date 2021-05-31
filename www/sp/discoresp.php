<?php

/**
 * Return page of the eIDAS country selector. Will go on with the authentication process
 */


if (! array_key_exists('AuthID', $_REQUEST)) {
    throw new SimpleSAML\Error\BadRequest('Missing AuthID to country selector response handler');
}

if (! array_key_exists('country', $_REQUEST)) {
    throw new SimpleSAML\Error\BadRequest('Missing country to country selector response handler');
}


$state = SimpleSAML\Auth\State::loadState($_REQUEST['AuthID'], 'clave:sp:sso');

if (! array_key_exists('clave:sp:AuthId', $state)) {
    SimpleSAML\Logger::error('clave:sp:AuthId key missing in $state array');
}
$sourceId = $state['clave:sp:AuthId'];

if (! array_key_exists('clave:sp:idpEntityID', $state)) {
    SimpleSAML\Logger::error('clave:sp:idpEntityID key missing in $state array');
}
$idpEntityId = $state['clave:sp:idpEntityID'];


$source = SimpleSAML\Auth\Source::getById($sourceId);
if ($source === null) {
    throw new Exception('Could not find authentication source with id ' . $sourceId);
}
if (! ($source instanceof SimpleSAML\Module\clave\Auth_Source_SP)) {
    throw new SimpleSAML\Error\Exception("Source -${sourceId}- type (SimpleSAML\Module\clave\Auth_Source_SP) changed?");
}


$state['country'] = $_REQUEST['country'];  // TODO SEGUIR usar este country en el startSSO, adaptar tb el discovery en el bridge.  // TODO: on startSSO, make sure this attr is not duplicated in the forwarded ones.


$idp = $idpEntityId;



$source->startSSO($idp, $state);
