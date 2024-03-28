<?php

class SnmpDiscoveryCollector extends Collector
{
	/** @var int The ID of the SNMP discovery application found with the given UUID */
	protected int $iApplicationID;
	/**
	 * @var array<string, array{ default_org_id: int, default_networkdevicetype_id: int, snmpcredentials_list: int[], dhcp_range_discovery_enabled: string }> List of subnets with their configured parameters
	 */
	protected array $aSubnets = [];
	/** @var array<int, array{ip: string, subnet_ip: string}> List of all the IP addresses to discover with their subnet IP */
	protected array $aIPAddresses = [];
	/** @var array<int, SnmpCredentials> Cache of potential SNMP credentials */
	protected static array $aSnmpCredentials = [];
	/** @var array<int, array{org_id: int, managementip_id: int, snmpcredentials_id: int}> */
	protected array $aDevices = [];
	/** @var int Number of IPs that didn't respond to any SNMP request */
	protected int $iFailedIPs = 0;
	
	/**
	 * @inheritDoc
	 * @return void
	 * @throws Exception
	 */
	public function Init(): void
	{
		parent::Init();
		
		// Check if modules are installed
		static::CheckModuleInstallation('sv-snmp-discovery', true);
		
		// Load SNMP discovery application settings
		$this->LoadApplicationSettings();
	}
	
	/**
	 * @return bool
	 * @throws Exception
	 */
	public function Prepare(): bool
	{
		// Load all responding IP addresses
		$this->LoadAllIPAddresses();
		
		// Load extra device info
		$this->LoadDevices();
		//$this->LoadAdditionalDevices();
		
		return parent::Prepare();
	}
	
	/**
	 * @return array|false
	 * @throws Exception
	 */
	protected function Fetch(): array|false
	{
		while ($iKey = key($this->aIPAddresses)) {
			next($this->aIPAddresses);
			
			// Discover IP addresses as network device
			if ($aData = $this->DiscoverDeviceByIP($iKey)) return $aData;
			else $this->iFailedIPs++;
		}
		
		return false;
	}
	
	/**
	 * @return void
	 * @throws Exception
	 */
	protected function Cleanup(): void
	{
		Utils::Log(LOG_NOTICE, $this->iFailedIPs . ' non responding devices.');
		parent::Cleanup();
	}
	
	/**
	 * @param array<string, string> $aPlaceHolders
	 * @return string|false
	 * @throws Exception
	 */
	public function GetSynchroDataSourceDefinition($aPlaceHolders = []): string|false
	{
		$aPlaceHolders['$uuid$'] = Utils::GetConfigurationValue('discovery_application_uuid');
		
		return parent::GetSynchroDataSourceDefinition($aPlaceHolders);
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
		foreach ($aHeaders as $sHeader) {
			if (($sHeader != 'primary_key') && !$this->HeaderIsAllowed($sHeader)) {
				if (!$this->AttributeIsOptional($sHeader)) {
					Utils::Log(LOG_WARNING, "Invalid column '$sHeader', will be ignored.");
				}
			} else {
				$this->aCSVHeaders[] = $sHeader;
			}
		}
		fputcsv($this->aCSVFile[$this->iFileIndex], $this->aCSVHeaders, $this->sSeparator);
	}
	
	/**
	 * @todo Workaround needed until PR merged in iTop
	 * @link https://github.com/Combodo/iTop/pull/541
	 * @param string $sHeader
	 * @return bool
	 */
	protected function HeaderIsAllowed(string $sHeader): bool
	{
		if (in_array($sHeader, [
			'snmp_sysname',
			'snmp_sysdescr',
			'snmp_syslocation',
			'snmp_syscontact',
		])) return true;
		
		/**
		 * @todo Workaround needed until PR merged in data-collector-base
		 * @link https://github.com/Combodo/itop-data-collector-base/pull/37
		 * @example return parent::HeaderIsAllowed($sHeader);
		 */
		return array_key_exists($sHeader, $this->aFields);
	}
	
	/**
	 * Check if the given module is installed in iTop
	 *
	 * @param string $sName Name of the module to be found
	 * @param bool $bRequired Whether to throw exceptions when module not found
	 * @return bool True when the given module is installed, false otherwise
	 * @throws Exception When the module is required but could not be found
	 *
	 * @todo Workaround needed until PR merged in data-collector-base
	 * @link https://github.com/Combodo/itop-data-collector-base/pull/39
	 */
	protected static function CheckModuleInstallation(string $sName, bool $bRequired = false): bool
	{
		$oRestClient = new RestClient();
		try {
			$aResults = $oRestClient->Get('ModuleInstallation', ['name' => $sName], 'name,version');
			if ($aResults['code'] != 0 || empty($aResults['objects'])) {
				throw new Exception($aResults['message'], $aResults['code']);
			}
			$aObject = current($aResults['objects']);
			Utils::Log(LOG_DEBUG, sprintf('iTop module %s version %s is installed.', $aObject['fields']['name'], $aObject['fields']['version']));
		} catch (Exception $e) {
			$sMessage = sprintf('%s iTop module %s is considered as not installed due to: %s', $bRequired ? 'Required' : 'Optional', $sName, $e->getMessage());
			if ($bRequired) throw new Exception($sMessage, 0, $e);
			else {
				Utils::Log(LOG_INFO, $sMessage);
				return false;
			}
		}
		return true;
	}
	
	/**
	 * Load the SNMP discovery application settings (ID and subnet to discover)
	 * @return void
	 * @throws Exception
	 */
	protected function LoadApplicationSettings(): void
	{
		$sUUID = Utils::GetConfigurationValue('discovery_application_uuid');
		$oRestClient = new RestClient();
		
		try {
			$aResults = $oRestClient->Get('SNMPDiscovery', ['uuid' => $sUUID], 'ipv4subnets_list,ipv6subnets_list');
			if ($aResults['code'] != 0 || empty($aResults['objects'])) {
				throw new Exception($aResults['message'], $aResults['code']);
			}
			
			$aDiscovery = current($aResults['objects']);
			$this->iApplicationID = (int)$aDiscovery['key'];
			
			Utils::Log(LOG_INFO, sprintf('An SNMP discovery application with UUID %s has been found in iTop.', $sUUID));
		} catch (Exception $e) {
			throw new Exception(sprintf('An SNMP discovery application with UUID %s could not be found: %s', $sUUID, $e->getMessage()), 0, $e);
		}
		
		// Prepare IPv4 subnet info
		foreach ($aDiscovery['fields']['ipv4subnets_list'] as $aSubnet) {
			$this->LoadSubnet($aSubnet);
		}
		
		// Prepare IPv6 subnet info
		foreach ($aDiscovery['fields']['ipv6subnets_list'] as $aSubnet) {
			$this->LoadSubnet($aSubnet);
		}
		
		Utils::Log(LOG_INFO, count($this->aSubnets) . ' subnets to discover.');
	}
	
	/**
	 * Prepare the subnet parameters list by the given subnet
	 * @param array{ip: string, org_id: string, default_networkdevicetype_id: string, snmpcredentials_list: int[], dhcp_range_discovery_enabled: string} $aSubnet
	 * @return void
	 * @throws Exception
	 */
	protected function LoadSubnet(array $aSubnet): void
	{
		if ($aSubnet['ipdiscovery_enabled'] == 'yes') {
			$this->aSubnets[$aSubnet['ip']] = [
				'default_org_id' => (int)$aSubnet['org_id'],
				'default_networkdevicetype_id' => (int)$aSubnet['default_networkdevicetype_id'],
				'snmpcredentials_list' => array_map(function ($aListItem) { return (int)$aListItem['snmpcredentials_id']; }, $aSubnet['snmpcredentials_list']),
				'dhcp_range_discovery_enabled' => $aSubnet['dhcp_range_discovery_enabled'],
			];
			
			if (empty($aSubnet['default_networkdevicetype_id'])) {
				Utils::Log(LOG_WARNING, sprintf('No default networkdevicetype_id set for subnet %s, creation of new devices might fail.', $aSubnet['ip']));
			}
		}
	}
	
	/**
	 * Load all IP addresses to discover from the subnet linked to the current SNMP discovery application
	 * @return void
	 * @throws Exception
	 */
	protected function LoadAllIPAddresses(): void
	{
		// Load IPv4 addresses to discover
		$aIPv4Addresses = static::LoadIPAddresses('IPv4Address', sprintf(<<<SQL
SELECT IPv4Address AS a
	JOIN IPv4Subnet AS s ON a.subnet_id = s.id
WHERE s.snmpdiscovery_id = %d
SQL, $this->iApplicationID));
		
		// Load IPv6 addresses to discover
		$aIPv6Addresses = static::LoadIPAddresses('IPv6Address', sprintf(<<<SQL
SELECT IPv6Address AS a
	JOIN IPv6Subnet AS s ON a.subnet_id = s.id
WHERE s.snmpdiscovery_id = %d
SQL, $this->iApplicationID));
		
		$this->aIPAddresses = $aIPv4Addresses + $aIPv6Addresses;
		Utils::Log(LOG_INFO, count($this->aIPAddresses) . ' addresses to process.');
	}
	
	/**
	 * Load IP addresses to discover by the given class and query
	 * @param 'IPv4Address'|'IPv6Address' $sClass The IP class to query
	 * @param string $sKeySpec The OQL to select addresses to discover
	 * @return array<int, array{ip: string, subnet_ip: string}>
	 * @throws Exception
	 */
	protected static function LoadIPAddresses(string $sClass, string $sKeySpec): array
	{
		$aIPAddresses = [];
		try {
			$oRestClient = new RestClient();
			
			$aResults = $oRestClient->Get($sClass, $sKeySpec, 'ip,subnet_ip,responds_to_ping');
			if ($aResults['code'] != 0) {
				throw new Exception($aResults['message'], $aResults['code']);
			}
			
			if (!empty($aResults['objects'])) foreach ($aResults['objects'] as $aIPAddress) {
				// Skip non responding IPs
				if ($aIPAddress['fields']['responds_to_ping'] != 'no') {
					$aIPAddresses[(int)$aIPAddress['key']] = $aIPAddress['fields'];
				} else Utils::Log(LOG_DEBUG, sprintf('Skipping non responding IP %s.', $aIPAddress['fields']['ip']));
			}
		} catch (Exception $e) {
			throw new Exception(sprintf('Could not load %s: %s', $sClass, $e->getMessage()));
		}
		
		return $aIPAddresses;
	}
	
	/**
	 * Load known devices' snmp credentials so the collector doesn't need to figure out again.
	 * @return void
	 * @throws Exception
	 */
	protected function LoadDevices(): void
	{
		try {
			$oRestClient = new RestClient();
			
			$aResults = $oRestClient->Get('NetworkDevice', sprintf('SELECT NetworkDevice WHERE snmpcredentials_id != 0 AND managementip_id IN(%s)', implode(',', array_keys($this->aIPAddresses))), 'org_id,managementip_id,snmpcredentials_id');
			if ($aResults['code'] != 0) {
				throw new Exception($aResults['message'], $aResults['code']);
			}
			
			if (!empty($aResults['objects'])) foreach ($aResults['objects'] as $aNetworkDevice) {
				$this->aDevices[(int) $aNetworkDevice['key']] = [
					'org_id' => (int) $aNetworkDevice['fields']['org_id'],
					'managementip_id' => (int) $aNetworkDevice['fields']['managementip_id'],
					'snmpcredentials_id' => (int) $aNetworkDevice['fields']['snmpcredentials_id'],
				];
			}
		} catch (Exception $e) {
			throw new Exception(sprintf('Could not load device credentials: %s', $e->getMessage()));
		}
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
	 * @param int $iKey ID of the IPAddress
	 * @return array{
	 *     primary_key: string,
	 *     org_id: int,
	 *     name: string,
	 *     networkdevicetype_id: int,
	 *     managementip_id: int,
	 *     snmpcredentials_id: int,
	 *     status: string,
	 *     serialnumber: ?string,
	 *     responds_to_snmp: 'yes',
	 *     snmp_last_discovery: string,
	 *     snmp_sysname: string,
	 *     snmp_sysdescr: string,
	 *     snmp_syscontact: string,
	 *     snmp_syslocation: string,
	 * }|null
	 * @throws Exception
	 */
	protected function DiscoverDeviceByIP(int $iKey): ?array
	{
		['ip' => $sIP, 'subnet_ip' => $sSubnetIP] = $this->aIPAddresses[$iKey];
		Utils::Log(LOG_DEBUG, sprintf('Discovering IP %s...', $sIP));
		
		// Prepare defaults
		$aDefaults = [
			'org_id' => $this->aSubnets[$sSubnetIP]['default_org_id'] ?? 0,
			'networkdevicetype_id' => $this->aSubnets[$sSubnetIP]['default_networkdevicetype_id'] ?? 0,
			'status' => Utils::GetConfigurationValue('default_status', 'implementation'),
		];
		
		// Prepare known credentials
		$aDeviceCredentials = $this->aSubnets[$sSubnetIP]['snmpcredentials_list'] ?? [];
		foreach ($this->aDevices as $aDevice)  {
			if ($aDevice['managementip_id'] == $iKey) {
				array_unshift($aDeviceCredentials, $aDevice['snmpcredentials_id']);
				$aDefaults['org_id'] = $aDevice['org_id'];
				break;
			}
		}
		
		// Try SNMP connection with each known credential
		foreach (array_unique($aDeviceCredentials) as $iCredentialsKey) {
			$oCredentials = static::LoadSnmpCredentials($iCredentialsKey);
			
			Utils::Log(LOG_DEBUG, sprintf('Trying credential %s...', $oCredentials->name));
			$oSNMP = static::LoadSNMPConnection($sIP, $oCredentials);
			
			$sysObjectID = @$oSNMP->get(/* SNMPv2-MIB::sysObjectID */ '.1.3.6.1.2.1.1.2.0');
			
			if ($sysObjectID === false) Utils::Log(LOG_DEBUG, $oSNMP->getError());
			else {
				Utils::Log(LOG_INFO, sprintf('IP %s responds to %s.', $sIP, $oCredentials->name));
				Utils::Log(LOG_DEBUG, 'Device sysObjectID: '. $sysObjectID);
				$sPrimaryKey = $sysObjectID . ' - ';
				
				// Find device serial number
				['serial' => $sSerial, 'load' => $bLoadSerial, 'primary_key' => $bUseAsPrimaryKey] = static::FindDeviceSerial($oSNMP, $sysObjectID);
				if (!is_null($sSerial) && $bUseAsPrimaryKey) {
					Utils::Log(LOG_DEBUG, 'Device serial: ' . $sSerial);
					$sPrimaryKey .= $sSerial;
				} else $sPrimaryKey .= $sIP;
				
				// Find device type
				// ToDo: mapping table on oid?
				
				// Load system table info
				[
					'.1.3.6.1.2.1.1.1.0' => $sSysDescr,
					'.1.3.6.1.2.1.1.4.0' => $sSysContact,
					'.1.3.6.1.2.1.1.5.0' => $sSysName,
					'.1.3.6.1.2.1.1.6.0' => $sSysLocation,
				] = @$oSNMP->get([
					/* SNMPv2-MIB::sysDescr */ '.1.3.6.1.2.1.1.1.0',
					/* SNMPv2-MIB::sysContact */ '.1.3.6.1.2.1.1.4.0',
					/* SNMPv2-MIB::sysName */ '.1.3.6.1.2.1.1.5.0',
					/* SNMPv2-MIB::sysLocation */ '.1.3.6.1.2.1.1.6.0',
				]);
				
				// Return device
				return [
					'primary_key' => $sPrimaryKey,
					'org_id' => $aDefaults['org_id'],
					'name' => $sSysName,
					'networkdevicetype_id' => $aDefaults['networkdevicetype_id'],
					'managementip_id' => $iKey,
					'snmpcredentials_id' => $iCredentialsKey,
					'status' => $aDefaults['status'],
					'serialnumber' => $bLoadSerial ? $sSerial : null,
					'responds_to_snmp' => 'yes',
					'snmp_last_discovery' => date('Y-m-d H:i:s'),
					'snmp_sysname' => $sSysName,
					'snmp_sysdescr' => trim($sSysDescr),
					'snmp_syscontact' => $sSysContact,
					'snmp_syslocation' => $sSysLocation,
				];
			}
		}
		
		Utils::Log(LOG_INFO, sprintf('IP %s does not respond.', $sIP));
		return null;
	}
	
	/**
	 * @param SNMP $oSNMP
	 * @param string $sSysObjectID
	 * @return array{serial: string, load: bool, primary_key: bool}|null
	 * @throws Exception
	 */
	protected static function FindDeviceSerial(SNMP $oSNMP, string $sSysObjectID): ?array
	{
		/** @var array $aSerialDetectionOptions */
		$aSerialDetectionOptions = Utils::GetConfigurationValue('serial_detection', []);
		
		foreach ($aSerialDetectionOptions as $aDetectionOption) {
			$sSysObjectIDMatch = $aDetectionOption['system_oid_match'];
			if (($sSysObjectIDMatch[0] == '/' && preg_match($sSysObjectIDMatch, $sSysObjectID)) || substr_compare($sSysObjectID, $sSysObjectIDMatch, 0, strlen($sSysObjectIDMatch)) === 0) {
				Utils::Log(LOG_DEBUG, 'sysObjectID matches with ' . $sSysObjectIDMatch);
				
				$bFound = false;
				$sSerial = null;
				$bLoadSerial = filter_var($aDetectionOption['use_as_serialnumber'] ?? false, FILTER_VALIDATE_BOOLEAN);
				$bPrimaryKey = filter_var($aDetectionOption['use_as_primary_key'] ?? $bLoadSerial, FILTER_VALIDATE_BOOLEAN);
				$sSerialOid = $aDetectionOption['serial_oid'];
				
				if ($aDetectionOption['method'] == 'get') {
					$sSerial = @$oSNMP->get($sSerialOid);
					$bFound = ($sSerial !== false);
				} else do {
					$aResult = @$oSNMP->getnext([$sSerialOid]);
					if (is_array($aResult)) {
						$sSerial = current($aResult);
						$sSerialOid = key($aResult);
						switch ($aDetectionOption['method']) {
							case 'getNextNonEmpty':
								$bFound = !empty($sSerial);
								break;
							case 'getNextValidMAC':
								$sPhysAddress = bin2hex($sSerial);
								$bFound = (strlen($sPhysAddress) == 12 && !empty(hexdec($sPhysAddress)));
								if ($bFound) $sSerial = implode(':', str_split($sPhysAddress, 2));
								break;
						}
					}
				} while (!$bFound && substr_count($sSerialOid, $aDetectionOption['serial_oid']));
				if ($bFound) {
					return ['serial' => $sSerial, 'load' => $bLoadSerial, 'primary_key' => $bPrimaryKey];
				}
			}
		}
		return null;
	}
	
	/**
	 * @param string $sHostname
	 * @param SnmpCredentials $oCredentials
	 * @return SNMP
	 */
	protected static function LoadSNMPConnection(string $sHostname, SnmpCredentials $oCredentials): SNMP
	{
		if (!empty($oCredentials->securityLevel)) {
			$oSNMP = new SNMP(SNMP::VERSION_3, $sHostname, $oCredentials->securityName);
			$oSNMP->setSecurity(
				$oCredentials->securityLevel,
				$oCredentials->authenticationProtocol,
				$oCredentials->authenticationPassphrase,
				$oCredentials->privacyProtocol,
				$oCredentials->privacyPassphrase,
				$oCredentials->contextName
			);
		} else $oSNMP = new SNMP(SNMP::VERSION_2c, $sHostname, $oCredentials->community);
		
		// Plain value retrieval
		$oSNMP->valueretrieval = SNMP_VALUE_PLAIN;
		// Numeric OID output format
		$oSNMP->oid_output_format = SNMP_OID_OUTPUT_NUMERIC;
		
		return $oSNMP;
	}
}
