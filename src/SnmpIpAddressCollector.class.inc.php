<?php

abstract class SnmpIPAddressCollector extends SnmpCollector
{
	/** @var int Flag to specify which IPs get validated (override) */
	protected const FilterFlag = FILTER_FLAG_NONE;

	/**
	 * Retrieve and prepare IPs discovered by {@see SnmpDiscoveryCollector}
	 * @return true
	 */
	public function Prepare(): bool
	{
		foreach (SnmpDiscoveryCollector::$aDiscoveredIPAddresses as $sKey => $aIP) {
			if (filter_var($aIP['ip'], FILTER_VALIDATE_IP, static::FilterFlag)) {
				$this->aData[] = [
					'primary_key' => $sKey,
					'status' => 'discovered',
				] + $aIP;
			}
		}

		return parent::Prepare();
	}

	/**
	 * Collect interface IP addresses
	 * @param SNMP $oSNMP
	 * @return array<int, array> Keyed by ifIndex
	 * @throws Exception
	 */
	public static function CollectAddresses(SNMP $oSNMP): array
	{
		$aAddresses = [];

		Utils::Log(LOG_DEBUG, "Collecting interface IPs...");

		$ipAddressIfIndex = @$oSNMP->walk('1.3.6.1.2.1.4.34.1.3', true);

		if ($ipAddressIfIndex !== false)  foreach ($ipAddressIfIndex as $sIndex => $iIfIndex) {

			$aIndex = array_map('intval', explode('.', $sIndex));
			$iAddrLen  = match ($aIndex[0]) {
				1, 3 => 4,
				2, 4 => 16,
				default => null,
			};

			if ($iAddrLen !== null && count($aIndex) >= 2 + $iAddrLen ) {
				$aAddresses[] = [
					'ip' => inet_ntop(pack('C*', ...array_slice($aIndex, 2, $iAddrLen))),
					'ifIndex' => $iIfIndex,
				];

			}
		}

		Utils::Log(LOG_DEBUG, sprintf('%d interface IPs collected', count($aAddresses)));
		return $aAddresses;
	}
}

class IPv4AddressCollector extends SnmpIPAddressCollector
{
	protected const FilterFlag = FILTER_FLAG_IPV4;
}

class IPv6AddressCollector extends SnmpIPAddressCollector
{
	protected const FilterFlag = FILTER_FLAG_IPV6;
}
