<?php

abstract class SnmpCollector extends Collector
{
	/** @var SnmpCredentials[] Cache of potential SNMP credentials */
	protected static array $aSnmpCredentials = [];

	/** @var array List of prepared data to be synchronised */
	protected array $aData = [];

	/**
	 * @inheritDoc
	 * @return void
	 * @throws Exception
	 */
	public function Init(): void
	{
		parent::Init();

		// Check if modules are installed
		Utils::CheckModuleInstallation('sv-snmp-discovery/1.3.0', true);
	}

	/**
	 * @param array<string, string> $aPlaceHolders
	 * @return string|false
	 * @throws Exception
	 */
	public function GetSynchroDataSourceDefinition($aPlaceHolders = []): string|false
	{
		$aPlaceHolders['$uuid$'] = Utils::GetConfigurationValue('discovery_application_uuid');

		return Collector::GetSynchroDataSourceDefinition($aPlaceHolders);
	}

	/**
	 * @todo Workaround needed until PR merged in data-collector-base
	 * @link https://github.com/Combodo/itop-data-collector-base/pull/37
	 * @param string[] $aHeaders
	 * @return void
	 * @throws Exception
	 */
	protected function AddHeader($aHeaders): void
	{
		$this->aCSVHeaders = array();
		foreach ($aHeaders as $sHeader)
		{
			if (($sHeader != 'primary_key') && !$this->HeaderIsAllowed($sHeader))
			{
				if (!$this->AttributeIsOptional($sHeader))
				{
					Utils::Log(LOG_WARNING, "Invalid column '$sHeader', will be ignored.");
				}
			}
			else
			{
				$this->aCSVHeaders[] = $sHeader;
			}
		}
		fputcsv($this->aCSVFile[$this->iFileIndex], $this->aCSVHeaders, $this->sSeparator);
	}

	/**
	 * @todo Workaround needed until PR merged in data-collector-base
	 * @link https://github.com/Combodo/itop-data-collector-base/pull/37
	 * @param string $sHeader
	 * @return bool
	 */
	protected function HeaderIsAllowed($sHeader)
	{
		return array_key_exists($sHeader, $this->aFields);
	}

	/**
	 * All fields can be NULL
	 * @param string $sAttCode
	 * @return true
	 */
	public function AttributeIsNullified($sAttCode)
	{
		return true;
	}

	/**
	 * @return array|false
	 */
	protected function Fetch(): bool|array
	{
		$aRow = current($this->aData);
		next($this->aData);
		return $aRow;
	}

	/**
	 * @param integer $iKey
	 * @return SnmpCredentials
	 * @throws Exception
	 */
	protected static function LoadSnmpCredentials(int $iKey): SnmpCredentials
	{
		if (!isset(static::$aSnmpCredentials[$iKey])) {
			$oRestClient = new RestClient();
			$aResults = $oRestClient->Get('SnmpCredentials', $iKey, 'name,community,security_level,security_name,auth_protocol,auth_passphrase,priv_protocol,priv_passphrase,context_name');

			if ($aResults['code'] != 0 || empty($aResults['objects'])) throw new Exception($aResults['message'], $aResults['code']);

			$aCredentials = current($aResults['objects']);
			static::$aSnmpCredentials[$iKey] = SnmpCredentials::fromArray($aCredentials['fields']);
		}

		return static::$aSnmpCredentials[$iKey];
	}

	/**
	 * Load devices by the given query.
	 * @param string $sKeySpec The OQL to select devices to load
	 * @return array<int, array{
	 *     org_id: int,
	 *     managementip_id: int,
	 *     snmpcredentials_id: int,
	 * }>
	 * @throws Exception
	 */
	protected static function LoadDevices(string $sKeySpec): array
	{
		$aDevices = [];
		try
		{
			$oRestClient = new RestClient();

			$aResults = $oRestClient->Get('NetworkDevice', $sKeySpec, 'org_id,managementip_id,snmpcredentials_id');
			if ($aResults['code'] != 0)
			{
				throw new Exception($aResults['message'], $aResults['code']);
			}

			if (!empty($aResults['objects'])) foreach ($aResults['objects'] as $aNetworkDevice)
			{
				$aDevices[(int) $aNetworkDevice['key']] = [
					'org_id'             => (int) $aNetworkDevice['fields']['org_id'],
					'managementip_id'    => (int) $aNetworkDevice['fields']['managementip_id'],
					'snmpcredentials_id' => (int) $aNetworkDevice['fields']['snmpcredentials_id'],
				];
			}
		}
		catch (Exception $e)
		{
			throw new Exception(sprintf('Could not load devices: %s', $e->getMessage()), 0, $e);
		}

		return $aDevices;
	}

	/**
	 * Load IP addresses to discover by the given class and query.
	 * @param 'IPv4Address'|'IPv6Address' $sClass The IP class to query
	 * @param string $sKeySpec The OQL to select addresses to discover
	 * @return array<int, array{ip: string, subnet_ip: string}>
	 * @throws Exception
	 */
	protected static function LoadIPAddresses(string $sClass, string $sKeySpec): array
	{
		$aIPAddresses = [];
		try
		{
			$oRestClient = new RestClient();

			$aResults = $oRestClient->Get($sClass, $sKeySpec, 'ip,subnet_ip,responds_to_ping');
			if ($aResults['code'] != 0)
			{
				throw new Exception($aResults['message'], $aResults['code']);
			}

			if (!empty($aResults['objects'])) foreach ($aResults['objects'] as $aIPAddress)
			{
				// Skip non responding IPs
				if ($aIPAddress['fields']['responds_to_ping'] != 'no')
				{
					$aIPAddresses[(int) $aIPAddress['key']] = $aIPAddress['fields'];
				}
				else Utils::Log(LOG_DEBUG, sprintf('Skipping non responding IP %s.', $aIPAddress['fields']['ip']));
			}
		}
		catch (Exception $e)
		{
			throw new Exception(sprintf('Could not load %s: %s', $sClass, $e->getMessage()), 0, $e);
		}

		return $aIPAddresses;
	}
}
