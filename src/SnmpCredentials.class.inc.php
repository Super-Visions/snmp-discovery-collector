<?php

class SnmpCredentials
{
	public string $name;
	public string $community;
	public ?string $securityLevel;
	public string $securityName;
	public ?string $authenticationProtocol;
	public string $authenticationPassphrase;
	public ?string $privacyProtocol;
	public string $privacyPassphrase;
	public string $contextName;
	
	/**
	 * @param array{
	 *     name: string,
	 *     community: string,
	 *     security_level: ?string,
	 *     security_name: string,
	 *     auth_protocol: ?string,
	 *     auth_passphrase: string,
	 *     priv_protocol: ?string,
	 *     priv_passphrase: string,
	 *     context_name: string,
	 * } $aSnmpCredentials
	 * @return static
	 */
	public static function fromArray(array $aSnmpCredentials): static
	{
		$oSelf = new static();
		$oSelf->name = $aSnmpCredentials['name'];
		$oSelf->community = $aSnmpCredentials['community'];
		$oSelf->securityLevel = $aSnmpCredentials['security_level'];
		$oSelf->securityName = $aSnmpCredentials['security_name'];
		$oSelf->authenticationProtocol = is_null($aSnmpCredentials['auth_protocol']) ? strtoupper($aSnmpCredentials['auth_protocol']) : null;
		$oSelf->authenticationPassphrase = $aSnmpCredentials['auth_passphrase'];
		$oSelf->privacyProtocol = is_null($aSnmpCredentials['priv_protocol']) ? strtoupper($aSnmpCredentials['priv_protocol']) : null;
		$oSelf->privacyPassphrase = $aSnmpCredentials['priv_passphrase'];
		$oSelf->contextName = $aSnmpCredentials['context_name'];
		return $oSelf;
	}
}
