<?php

abstract class SnmpCollector extends Collector
{
	/** @var SnmpCollectionPlan The current collection plan */
	protected SnmpCollectionPlan $oPlan;
	/** @var SnmpCredentials[] Cache of potential SNMP credentials */
	protected static array $aSnmpCredentials = [];
	/** @var array[] List of prepared data to be synchronised */
	protected array $aData = [];
	/** @var array<string, int> Header positions of the link set fields, indexed by field name */
	protected static array $aLinkSetFieldPositions = [];

	/**
	 * @inheritDoc
	 * @return void
	 * @throws Exception
	 */
	public function Init(): void
	{
		$this->oPlan = SnmpCollectionPlan::GetPlan();

		parent::Init();
	}

	/**
	 * @param array<string, string> $aPlaceHolders
	 * @return string|false
	 * @throws Exception
	 */
	public function GetSynchroDataSourceDefinition($aPlaceHolders = []): string|false
	{
		$sURL = Utils::GetConfigurationValue('itop_url');
		$aPlaceHolders['$uuid$'] = Utils::GetConfigurationValue('discovery_application_uuid');
		$aPlaceHolders['$url_icon$'] = sprintf('%s/env-production/sv-snmp-discovery/images/icons8-switch-48-search.png', $sURL);
		$aPlaceHolders['$url_application$'] = sprintf('%s/pages/UI.php?operation=details&class=SNMPDiscovery&id=%d', $sURL, $this->oPlan->GetApplicationID());

		return parent::GetSynchroDataSourceDefinition($aPlaceHolders);
	}

	protected function Fetch(): false|array
	{
		$aRow = current($this->aData);
		next($this->aData);
		return $aRow;
	}

	public function ReadCollectorConfig(): void
	{
		$this->aCollectorConfig = [];
	}

	/**
	 * @inheritDoc
	 * @throws Exception
	 */
	protected function OpenCSVFile(): bool
	{
		$sFileFormat = '%s-%0*d.csv';
		$iEstimatedFileCount = ceil(count($this->aData) / Utils::GetConfigurationValue('max_chunk_size', 1000)) ;
		if ($this->MustProcessBeforeSynchro()) {
			$sDataFile = Utils::GetDataFilePath(sprintf($sFileFormat, get_class($this) . '.raw', 1 + (int)log10($iEstimatedFileCount), 1 + $this->iFileIndex));
		} else {
			$sDataFile = Utils::GetDataFilePath(sprintf($sFileFormat, get_class($this), 1 + (int)log10($iEstimatedFileCount), 1 + $this->iFileIndex));
		}
		$this->aCSVFile[$this->iFileIndex] = @fopen($sDataFile, 'wb');

		if ($this->aCSVFile[$this->iFileIndex] === false) {
			throw new IOException("Unable to open the file '$sDataFile' for writing.");
		} else {
			Utils::Log(LOG_INFO, "Writing to file '$sDataFile'.");
		}

		return true;
	}

	/**
	 * Lookup the linked objects of a JSON encoded link set field and replace the field value
	 * with the link set containing only the links whose target object was found.
	 *
	 * @param array $aLineData The current CSV line data
	 * @param int $iLineIndex Index of the line in the current CSV file
	 * @param string $sFieldName Name of the CSV field holding the JSON encoded links
	 * @param LookupTable $oLookup Lookup table used to resolve the linked objects
	 * @param string[] $aSearchKeys Fields used to search the linked object
	 * @param string $sLinkKey Key of the linked object inside each link (e.g. `vlan_id`)
	 * @return void
	 */
	protected function ProcessLinkSetLookup(array &$aLineData, int $iLineIndex, string $sFieldName, LookupTable $oLookup, array $aSearchKeys, string $sLinkKey): void
	{
		$this->aCSVHeaders;
		if ($iLineIndex === 0) {
			static::$aLinkSetFieldPositions[$sFieldName] = array_search($sFieldName, $aLineData);
			return;
		}

		$iFieldPos = static::$aLinkSetFieldPositions[$sFieldName];
		$aLookupLinks = json_decode($aLineData[$iFieldPos], true);
		$aFoundLinks = [];
		foreach ($aLookupLinks as $iLinkIndex => $aLookupLink) {
			$aLookupLink[$sLinkKey]['id'] = null;
			$aLookupLineHeaders = array_keys($aLookupLink[$sLinkKey]);
			$aLookupLineValues = array_values($aLookupLink[$sLinkKey]);

			if ($iLinkIndex === 0)  $oLookup->Lookup($aLookupLineHeaders, $aSearchKeys, 'id', 0);
			if ($oLookup->Lookup($aLookupLineValues, $aSearchKeys, 'id', $iLinkIndex + 1)) {
				$aLookupLink[$sLinkKey] = $aLookupLineValues[array_search('id', $aLookupLineHeaders)];
				$aFoundLinks[] = $aLookupLink;
			}
		}

		$aLineData[$iFieldPos] = static::ImplodeLinkSet($aFoundLinks);
	}

	/**
	 * Format the given linkset rows
	 * @param array[] $aData array of links as associative arrays
	 * @param string $sRowSeparator
	 * @param string $sAttributeSeparator
	 * @param string $sValueSeparator
	 * @param string $sAttributeQualifier
	 * @return string
	 */
	protected static function ImplodeLinkSet(array $aData, string $sRowSeparator = '|', string $sAttributeSeparator = ';', string $sValueSeparator = ':', string $sAttributeQualifier = "'"): string
	{
		$aRows = [];
		foreach ($aData as $aRow) {
			$aRowAttributes = [];
			foreach ($aRow as $sKey => $value) {
				$rStream = fopen('php://memory', 'r+');
				fputcsv($rStream, [$value], enclosure: $sAttributeQualifier, eol: '');
				rewind($rStream);
				$aRowAttributes[] = $sKey . $sValueSeparator . stream_get_contents($rStream);
				fclose($rStream);
			}
			$aRows[] = implode($sAttributeSeparator, $aRowAttributes);
		}
		return implode($sRowSeparator, $aRows);
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
			/** @noinspection SpellCheckingInspection */
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
