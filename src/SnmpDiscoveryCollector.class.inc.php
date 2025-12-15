<?php
use PhpAmqpLib\Channel\AMQPChannel;
use PhpAmqpLib\Connection\AMQPStreamConnection;
use PhpAmqpLib\Exception\AMQPTimeoutException;
use PhpAmqpLib\Message\AMQPMessage;

class SnmpDiscoveryCollector extends SnmpCollector
{
	/** @var int The ID of the SNMP discovery application found with the given UUID */
	protected int $iApplicationID;
	/** @var bool Whether distributed collection is enabled */
	protected bool $bDistributed;
	/** @var array<string, array{
	 *     default_org_id: int,
	 *     default_networkdevicetype_id: int,
	 *     snmpcredentials_list: int[],
	 *     dhcp_range_discovery_enabled: string,
	 * }> List of subnets with their configured parameters
	 */
	protected array $aSubnets = [];
	/** @var array<int, array{ip: string, subnet_ip: string}> List of all the IP addresses to discover with their subnet IP */
	protected array $aIPAddresses = [];
	/** @var array<int, array{org_id: int, managementip_id: int, snmpcredentials_id: int}> */
	protected array $aDevices = [];
	/** @var int Number of IPs that didn't respond to any SNMP request */
	protected int $iFailedIPs = 0;
	/** @var AMQPChannel The connected AMQP channel */
	protected AMQPChannel $oChannel;
	/** @var string Name of the RPC queue on AMQP */
	protected string $sQueue;
	/** @var AMQPMessage The message containing the result from the worker */
	protected AMQPMessage $oResponseMessage;
	/** @var int The timestamp when the worker needs to quit */
	protected int $iTimeout;
	/**
	 * @var array{
	 *     aggregatelinks_list: array,
	 *     networkdevicevirtualinterfaces_list: array,
	 *     physicalinterface_list: array,
	 * } List of discovered interfaces to be used by other collectors
	 */
	public static array $aDiscoveredInterfaces = [
		AggregateLinkCollector::InterfaceList => [],
		VirtualInterfaceCollector::InterfaceList => [],
		PhysicalInterfaceCollector::InterfaceList => [],
	];
	/**
	 * @var array<string, string[]> List of discovered Models ordered by Brand
	 */
	public static array $aDiscoveredModels = [];
	/**
	 * @var array<string, string[]> List of discovered IOS Versions ordered by Brand
	 */
	public static array $aDiscoveredVersions = [];
	protected static MappingTable $oSysOidBrandMapping;
	protected static MappingTable $oSysOidModelMapping;
	protected static MappingTable $oSysDescrBrandMapping;
	protected static MappingTable $oSysDescrModelMapping;
	protected static MappingTable $oSysDescrVersionMapping;
	protected static LookupTable $oModelLookup;
	protected static LookupTable $oVersionLookup;
	/**
	 * @var array<string, array> Cached list of contacts for each lookup spec
	 */
	protected static array $aLookupContacts = [];

	/**
	 * @inheritDoc
	 * @return void
	 * @throws Exception
	 */
	public function Init(): void
	{
		parent::Init();

		// Load SNMP discovery application settings
		$this->LoadApplicationSettings();
		
		// Initiate distributed collection
		$this->bDistributed = filter_var(Utils::GetConfigurationValue('amqp_enabled', false), FILTER_VALIDATE_BOOLEAN);
		if ($this->bDistributed) $this->InitMessageQueue();

		$this->InitMappingTables();
	}
	
	/**
	 * @return true
	 * @throws Exception
	 */
	public function Prepare(): bool
	{
		// Load all responding IP addresses
		$this->LoadAllIPAddresses();
		
		// Load extra device info
		$this->LoadAllDevices();
		
		// Prepare distributed collection
		if ($this->bDistributed) $this->PopulateMessageQueue();
		
		return parent::Prepare();
	}

	/**
	 * Allow process of `model_id` and `iosversion_id`.
	 * @return true
	 */
	protected function MustProcessBeforeSynchro(): bool
	{
		return true;
	}

	/**
	 * Initialise needed lookup tables
	 * @return void
	 * @throws Exception
	 */
	protected function InitProcessBeforeSynchro(): void
	{
		static::$oModelLookup = new LookupTable(/** @lang SQL */ "SELECT Model WHERE type = 'NetworkDevice'", ['brand_name','name']);
		static::$oVersionLookup = new LookupTable( /** @lang SQL */ 'SELECT IOSVersion', ['brand_name', 'name']);
	}

	/**
	 * Process of `model_id`, `iosversion_id` and `contacts_list` before synchro.
	 * @inheritDoc
     * @throws Exception
	 */
	protected function ProcessLineBeforeSynchro(&$aLineData, $iLineIndex): void
	{
		static::$oModelLookup->Lookup($aLineData, ['brand_id','model_id'], 'model_id', $iLineIndex, true);
		static::$oVersionLookup->Lookup($aLineData, ['brand_id','iosversion_id'], 'iosversion_id', $iLineIndex, true);
		static::ProcessContactsLookup($aLineData, $iLineIndex, 'contacts_list');
	}

	/**
	 * @return array|false
	 * @throws Exception
	 */
	protected function Fetch(): array|false
	{
		// Collect asynchronously discovered network devices
		while ($this->bDistributed && !empty($this->aIPAddresses))
		{
			// Wait until new message arrives
			try {
				$this->oChannel->wait(timeout: 60);
			} catch (AMQPTimeoutException $e) {
				$this->oChannel->queue_purge($this->sQueue);
				Utils::Log(LOG_ERR, $e->getMessage());
				break;
			}
			$sBody = $this->oResponseMessage->getBody();
			$iKey = $this->oResponseMessage->get('correlation_id');
			
			// Remove IP from list
			['ip' => $sIP] = $this->aIPAddresses[$iKey];
			unset($this->aIPAddresses[$iKey]);
			Utils::Log(LOG_DEBUG, sprintf('Received results for IP %s: %s', $sIP, $sBody !== 'null' ? 'OK' : 'NOK'));
			
			// Process results
			if ($aData = json_decode($sBody, true)) return $this->PrepareFetchData($aData);
			else $this->iFailedIPs++;
		}
		
		// Collect synchronously
		while ($iKey = key($this->aIPAddresses)) {
			next($this->aIPAddresses);
			
			[
				'ip' => $sIP,
				'defaults' => $aDefaults,
				'credentials' => $aDeviceCredentials,
			] = $this->PrepareDiscoverDeviceByIP($iKey);
			
			// Discover IP addresses as network device
			if ($aData = static::DiscoverDeviceByIP($iKey, $sIP, $aDefaults, $aDeviceCredentials)) return $this->PrepareFetchData($aData);
			else $this->iFailedIPs++;
		}
		
		return false;
	}

	/**
	 * Prepare the data to be returned to Fetch so it only includes allowed fields
	 * @param array $aData
	 * @return array{
	 *      primary_key: string,
	 *      org_id: int,
	 *      name: string,
	 *      networkdevicetype_id: int,
	 *      managementip_id: int,
	 *      snmpcredentials_id: int,
	 *      status: string,
	 *      serialnumber: ?string,
	 *      responds_to_snmp: 'yes',
	 *      snmp_last_discovery: string,
	 *      snmp_sysname: string,
	 *      snmp_sysdescr: string,
	 *      snmp_syslocation: string,
	 *      snmp_syscontact: string,
	 *      snmp_sysuptime: int,
	 *  }
	 */
	protected function PrepareFetchData(array $aData): array
	{
		/**
		 * Update interface `primary_key` and add fields needed for device lookup
		 * @param array $aInterface
		 * @return array
		 */
		$cPrepareInterface = function (array $aInterface) use ($aData) {
			$aInterface['primary_key'] = sprintf('%s - %d', $aData['primary_key'], $aInterface['primary_key']);
			foreach (SnmpInterfaceCollector::DeviceLookupFields as $sField) $aInterface[$sField] = $aData[$sField];
			return $aInterface;
		};

		$sBrand = $aData['brand_id'];
		$sModel = $aData['model_id'];
		$sVersion = $aData['iosversion_id'];

		// Prepare data for Model collection
		if (!isset(static::$aDiscoveredModels[$sBrand])) static::$aDiscoveredModels[$sBrand] = [$sModel];
		elseif (!in_array($sModel, static::$aDiscoveredModels[$sBrand])) static::$aDiscoveredModels[$sBrand][] = $sModel;

		// Prepare data for IOSVersion collection
		if (!isset(static::$aDiscoveredVersions[$sBrand])) static::$aDiscoveredVersions[$sBrand] = [$sVersion];
		elseif (!in_array($sVersion, static::$aDiscoveredVersions[$sBrand])) static::$aDiscoveredVersions[$sBrand][] = $sVersion;

		// Prepare data for interface collection
		foreach (array_keys(static::$aDiscoveredInterfaces) as $sField)
			if (isset($aData[$sField])) {
				static::$aDiscoveredInterfaces[$sField] += array_map($cPrepareInterface, $aData[$sField]);
				unset($aData[$sField]);
			}

		return $aData;
	}
	
	/**
	 * Close connection and csv files.
	 * @return void
	 * @throws Exception
	 */
	protected function Cleanup(): void
	{
		if ($this->bDistributed) $this->oChannel->getConnection()->close();
		
		Utils::Log(LOG_NOTICE, $this->iFailedIPs . ' non responding devices.');
		parent::Cleanup();
	}

	/**
	 * Initiate sub-collectors after discovery collector.
	 * @param int $iMaxChunkSize
	 * @return bool
	 * @throws Exception
	 */
	public function Collect($iMaxChunkSize = 0): bool
	{
		if (!parent::Collect($iMaxChunkSize)) return false;

		$aExtraCollectors = [
			ModelCollector::class,
			IOSVersionCollector::class,
		];

		foreach ($aExtraCollectors as $sCollector)
		{
			$oCollector = new $sCollector();
			$oCollector->Init();

			if (!$oCollector->Collect($iMaxChunkSize)) return false;
		}

		return true;
	}

	/**
	 * @todo Workaround needed until PR merged in iTop
	 * @link https://github.com/Combodo/iTop/pull/541
	 * @param string $sHeader
	 * @return bool
	 */
	protected function HeaderIsAllowed($sHeader): bool
	{
		if (in_array($sHeader, [
			'snmp_sysname',
			'snmp_sysdescr',
			'snmp_syslocation',
			'snmp_syscontact',
			'snmp_sysuptime',
		])) return true;

		return parent::HeaderIsAllowed($sHeader);
	}

	/**
	 * @inheritDoc
	 */
	public function AttributeIsOptional($sAttCode): bool
	{
		return match ($sAttCode)
		{
			'tickets_list' => true,
			default => parent::AttributeIsOptional($sAttCode),
		};
	}

	/**
	 * Load the SNMP discovery application ID and subnet(s) to discover.
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
	 * Prepare the subnet parameters list by the given subnet.
	 * @param array{
	 *     ip: string,
	 *     org_id: string,
	 *     default_networkdevicetype_id: string,
	 *     snmpcredentials_list: int[],
	 *     dhcp_range_discovery_enabled: string,
	 * } $aSubnet
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
	 * Load all IP addresses to discover from the subnet linked to the current SNMP discovery application.
	 * @return void
	 * @throws Exception
	 */
	protected function LoadAllIPAddresses(): void
	{
		// Load IPv4 addresses to discover
		$aIPv4Addresses = static::LoadIPAddresses('IPv4Address', sprintf(<<<SQL
SELECT IPv4Address AS a
	JOIN IPv4Subnet AS s ON a.subnet_id = s.id
WHERE s.snmpdiscovery_id = %d AND a.status != 'reserved'
SQL, $this->iApplicationID));
		
		// Load IPv6 addresses to discover
		$aIPv6Addresses = static::LoadIPAddresses('IPv6Address', sprintf(<<<SQL
SELECT IPv6Address AS a
	JOIN IPv6Subnet AS s ON a.subnet_id = s.id
WHERE s.snmpdiscovery_id = %d AND a.status != 'reserved'
SQL, $this->iApplicationID));
		
		$this->aIPAddresses = $aIPv4Addresses + $aIPv6Addresses;
		Utils::Log(LOG_INFO, count($this->aIPAddresses) . ' addresses to discover.');
	}

	/**
	 * Load all known devices' snmp credentials so the collector doesn't need to figure out again.
	 * @return void
	 * @throws Exception
	 */
	protected function LoadAllDevices(): void
	{
		// Load known devices
		if (!empty($this->aIPAddresses)) $this->aDevices = static::LoadDevices(sprintf( /** @lang SQL */ 'SELECT NetworkDevice WHERE snmpcredentials_id != 0 AND managementip_id IN(%s)', implode(',', array_keys($this->aIPAddresses))));
		Utils::Log(LOG_INFO, count($this->aDevices) . ' already known devices.');
		
		try {
			$sAdditionalDeviceWhere = Utils::GetConfigurationValue('additional_device_where');
			if (empty($sAdditionalDeviceWhere)) return;
			
			// Load additional devices
			$aAdditionalDevices = static::LoadDevices(sprintf( /** @lang SQL */ "SELECT NetworkDevice WHERE %s AND snmpcredentials_id != 0 AND id NOT IN(%s)", $sAdditionalDeviceWhere, implode(',', array_keys($this->aDevices)) ?: 0));
			if (empty($aAdditionalDevices)) return;
			
			// Also load IP addresses for additional devices
			$sAdditionalIPs = implode(',', array_map(function ($aDevice) { return $aDevice['managementip_id']; }, $aAdditionalDevices));
			$aIPv4Addresses = static::LoadIPAddresses('IPv4Address', sprintf( /** @lang SQL */ 'SELECT IPv4Address WHERE id IN(%s)', $sAdditionalIPs));
			$aIPv6Addresses = static::LoadIPAddresses('IPv6Address', sprintf( /** @lang SQL */ 'SELECT IPv6Address WHERE id IN(%s)', $sAdditionalIPs));
			
			$this->aDevices += $aAdditionalDevices;
			$this->aIPAddresses += $aIPv4Addresses + $aIPv6Addresses;
			
			Utils::Log(LOG_INFO, count($aIPv4Addresses + $aIPv6Addresses) . ' additional addresses to process.');
			
		} catch (Exception $e) {
			throw new Exception(sprintf('Could not load additional devices: %s', $e->getMessage()), 0, $e);
		}
	}

	/**
	 * Initialise the mapping tables used to detect the Brand, Model and IOS Version.
	 * @return void
	 * @throws Exception
	 */
	public function InitMappingTables(): void
	{
		static::$oSysOidBrandMapping = new MappingTable('sysObjectID_brand_mapping');
		static::$oSysOidModelMapping = new MappingTable('sysObjectID_model_mapping');
		static::$oSysDescrBrandMapping = new MappingTable('sysDescr_brand_mapping');
		static::$oSysDescrModelMapping = new MappingTable('sysDescr_model_mapping');
		static::$oSysDescrVersionMapping = new MappingTable('sysDescr_version_mapping');
	}

	/**
	 * Initiate connection to AMQP server and declare the RPC queue.
	 * @return void
	 * @throws Exception
	 */
	public function InitMessageQueue(): void
	{
		// Connect to AMQP server
		$oConnection = new AMQPStreamConnection(
			Utils::GetConfigurationValue('amqp_host', 'localhost'),
			filter_var(Utils::GetConfigurationValue('amqp_port', 5672), FILTER_VALIDATE_INT),
			Utils::GetConfigurationValue('amqp_user', 'guest'),
			Utils::GetConfigurationValue('amqp_password', 'guest')
		);
		if ($oConnection->isConnected()) Utils::Log(LOG_DEBUG, 'Connected to AMQP.');
		
		// Create AMQP channel
		$this->oChannel = $oConnection->channel();
		$this->oChannel->basic_qos(0, 1, false);
		
		// Declare AMQP RPC queue
		$sUUID = Utils::GetConfigurationValue('discovery_application_uuid');
		[$this->sQueue] = $this->oChannel->queue_declare(sprintf('%s-%s', $this->GetName(), $sUUID), auto_delete: false);
	}
	
	/**
	 * Prepare default values and list of credentials to use for device discovery.
	 * @param int $iKey ID of the IPAddress
	 * @return array{
	 *     ip: string,
	 *     defaults: array{
	 *         org_id: int,
	 *         networkdevicetype_id: int,
	 *         status: string,
	 *     },
	 *     credentials: int[],
	 * }
	 * @throws Exception
	 */
	public function PrepareDiscoverDeviceByIP(int $iKey): array
	{
		['ip' => $sIP, 'subnet_ip' => $sSubnetIP] = $this->aIPAddresses[$iKey];
		
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
		
		return [
			'ip' => $sIP,
			'defaults' => $aDefaults,
			'credentials' => array_unique($aDeviceCredentials),
		];
	}
	
	/**
	 * Send all IPs to be discovered to the RPC queue.
	 * @return void
	 * @throws Exception
	 */
	protected function PopulateMessageQueue(): void
	{
		// Create and consume the callback queue
		[$sCallbackQueue] = $this->oChannel->queue_declare(exclusive: true);
		Utils::Log(LOG_DEBUG, sprintf('AMQP callback queue: %s.', $sCallbackQueue));
		$this->oChannel->basic_consume(
			queue: $sCallbackQueue,
			no_ack: true,
			callback: function (AMQPMessage $oMessage){
				$this->oResponseMessage = $oMessage;
				$this->oChannel->stopConsume();
			}
		);
		
		foreach (array_keys($this->aIPAddresses) as $iKey)
		{
			$oMessage = new AMQPMessage(
				json_encode($this->PrepareDiscoverDeviceByIP($iKey)),
				[
					'content_type' => 'application/json',
					'reply_to' => $sCallbackQueue,
					'correlation_id' => $iKey,
					'delivery_mode' => AMQPMessage::DELIVERY_MODE_PERSISTENT,
				],
			);
			
			$this->oChannel->basic_publish($oMessage, routing_key: $this->sQueue);
		}
	}
	
	/**
	 * Start the worker by listening to the correct queue.
	 * @param int $iDuration Time in seconds until the worker stops
	 * @return void
	 * @throws ErrorException
	 */
	public function StartWorker(int $iDuration): void
	{
		$sConsumerTag = $this->oChannel->basic_consume($this->sQueue, callback: [$this, 'ProcessRequest']);
		Utils::Log(LOG_DEBUG, sprintf('AMQP consumer tag: %s.', $sConsumerTag));
		
		$this->iTimeout = time() + $iDuration;
		
		// Start consuming
		$this->oChannel->consume();
	}
	
	/**
	 * Process an incoming worker message.
	 * @param AMQPMessage $oRequest
	 * @return void
	 * @throws Exception
	 */
	public function ProcessRequest(AMQPMessage $oRequest): void
	{
		// Unpack request payload
		[
			'ip' => $sIP,
			'defaults' => $aDefaults,
			'credentials' => $aDeviceCredentials,
		] = json_decode($oRequest->getBody(), true);
		$iKey = $oRequest->get('correlation_id');
		
		// Discover IP addresses as network device
		$oResponse = new AMQPMessage(
			json_encode(static::DiscoverDeviceByIP($iKey, $sIP, $aDefaults, $aDeviceCredentials)),
			[
				'content_type' => 'application/json',
				'correlation_id' => $iKey,
			]
		);
		
		// Send results back
		Utils::Log(LOG_DEBUG, sprintf('Replying to %s', $oRequest->get('reply_to')));
		$this->oChannel->basic_publish($oResponse, routing_key: $oRequest->get('reply_to'));
		$oRequest->ack();
		
		// Stop worker when duration is passed
		if (time() >= $this->iTimeout)
			$this->oChannel->getConnection()->close();
	}
	
	/**
	 * Tries the list of given credentials and returns the discovered network device info.
	 * @param int $iKey ID of the IPAddress
	 * @param string $sIP The IP address to discover
	 * @param array $aDefaults Some default values
	 * @param int[] $aDeviceCredentials List of credentials to use
	 * @return array{
	 *     primary_key: string,
	 *     org_id: int,
	 *     name: string,
	 *     networkdevicetype_id: int,
	 *     managementip_id: int,
	 *     snmpcredentials_id: int,
	 *     status: string,
	 *     serialnumber: ?string,
	 *     brand_id: ?string,
	 *     model_id: ?string,
	 *     iosversion_id: ?string,
	 *     responds_to_snmp: 'yes',
	 *     snmp_last_discovery: string,
	 *     snmp_sysname: string,
	 *     snmp_sysdescr: string,
	 *     snmp_syslocation: string,
	 *     snmp_syscontact: string,
	 *     snmp_sysuptime: int,
	 *     physicalinterface_list: array,
	 *     networkdevicevirtualinterfaces_list: array,
	 *     aggregatelinks_list: array,
	 * }|null
	 * @throws Exception
	 */
	public static function DiscoverDeviceByIP(int $iKey, string $sIP, array $aDefaults, array $aDeviceCredentials): ?array
	{
		Utils::Log(LOG_DEBUG, sprintf('Discovering IP %s...', $sIP));
		
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
				[
					'serial' => $sSerial,
					'load' => $bLoadSerial,
					'primary_key' => $bUseAsPrimaryKey,
				] = static::FindDeviceSerial($oSNMP, $sysObjectID);
				if (!is_null($sSerial) && $bUseAsPrimaryKey) {
					Utils::Log(LOG_DEBUG, 'Device serial: ' . $sSerial);
					$sPrimaryKey .= $sSerial;
				} else $sPrimaryKey .= $sIP;
				
				// Load system table info
				[
					'.1.3.6.1.2.1.1.1.0' => $sSysDescr,
					'.1.3.6.1.2.1.1.3.0' => $sSysUptime,
					'.1.3.6.1.2.1.1.4.0' => $sSysContact,
					'.1.3.6.1.2.1.1.5.0' => $sSysName,
					'.1.3.6.1.2.1.1.6.0' => $sSysLocation,
				] = @$oSNMP->get([
					/* SNMPv2-MIB::sysDescr */    '.1.3.6.1.2.1.1.1.0',
					/* SNMPv2-MIB::sysUptime */   '.1.3.6.1.2.1.1.3.0',
					/* SNMPv2-MIB::sysContact */  '.1.3.6.1.2.1.1.4.0',
					/* SNMPv2-MIB::sysName */     '.1.3.6.1.2.1.1.5.0',
					/* SNMPv2-MIB::sysLocation */ '.1.3.6.1.2.1.1.6.0',
				]);

				// Do not record this device if SNMP GET failed.
				if ($oSNMP->getErrno() !== SNMP::ERRNO_NOERROR) {
					Utils::Log(LOG_WARNING, sprintf('Skipping, SNMP GET failed: %s', $oSNMP->getError()));
					return null;
				}

				// Detect Brand/Model from translated sysObjectID
				$sBrand = $sModel = null;
				$oSNMPWithTranslate = static::LoadSNMPConnection($sIP, $oCredentials, SNMP_OID_OUTPUT_MODULE);
				$sTranslatedSysObjectID = @$oSNMPWithTranslate->get(/* SNMPv2-MIB::sysObjectID */ '.1.3.6.1.2.1.1.2.0');
				if ($sTranslatedSysObjectID) {
					Utils::Log(LOG_DEBUG, sprintf('Translated sysObjectID: %s', $sTranslatedSysObjectID));
					$sBrand = static::$oSysOidBrandMapping->MapValue($sTranslatedSysObjectID);
					$sModel = static::$oSysOidModelMapping->MapValue($sTranslatedSysObjectID);
				}

				// Detect Brand/Model/Version from sysDescr
				$sSysDescr = trim($sSysDescr);
				$sBrand = static::$oSysDescrBrandMapping->MapValue($sSysDescr, $sBrand);
				$sModel = static::$oSysDescrModelMapping->MapValue($sSysDescr, $sModel);
				$sVersion = static::$oSysDescrVersionMapping->MapValue($sSysDescr);

				// Detect linked contacts from sysLocation
				$aContacts = [];
				$aMatchRules = [
					/** @lang RegExp */ '/(?<friendlyname>\w[\w ]+?)(\s+)(?:[:\-\/](?2))?<?(?<email>\b\S+@\S+\b)>?/',
					/** @lang RegExp */ '/(?<friendlyname>\w.+?)(\s*)(?:[:\-\/](?2))?(?<phone>(?:00|\+)\d{1,4}\/?(?:\s?\d{2,})+)/',
					/** @lang RegExp */ '/^(?<org_name>[\w\s]+) - (?<friendlyname>[\w\s]+)$/',
					/** @lang RegExp */ '/<?(?<email>\b\S+@\S+\b)>?/',
				];
				$cFilter = fn($sValue, $sKey) => is_string($sKey) && !is_null($sValue);
				foreach ($aMatchRules as $sMatchRule) {
					if (preg_match_all($sMatchRule, $sSysContact, $aMatches, PREG_SET_ORDER | PREG_UNMATCHED_AS_NULL)) {
						foreach ($aMatches as $aMatch) {
							Utils::Log(LOG_DEBUG, sprintf('Contact details detected from sysContact: %s', $aMatch[0]));
							$aContact = array_filter($aMatch, $cFilter, ARRAY_FILTER_USE_BOTH);
							if (!empty($aContact)) $aContacts[] = $aContact;
						}
					}
				}
				if (empty($aContacts) && !empty($sSysContact)) $aContacts[] = ['friendlyname' => $sSysContact];

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
					'brand_id' => $sBrand,
					'model_id' => !empty($sBrand) ? $sModel : null,
					'iosversion_id' => !empty($sBrand) ? $sVersion : null,
					'responds_to_snmp' => 'yes',
					'snmp_last_discovery' => date(Utils::GetConfigurationValue('date_format', 'Y-m-d H:i:s')),
					'snmp_sysname' => $sSysName,
					'snmp_sysdescr' => $sSysDescr,
					'snmp_syslocation' => $sSysLocation,
					'snmp_syscontact' => $sSysContact,
					'snmp_sysuptime' => (int) round($sSysUptime/100),
					'contacts_list' => json_encode($aContacts),
				] + SnmpInterfaceCollector::CollectInterfaces($oSNMP);
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
		/** @var array[] $aSerialDetectionOptions */
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
	 * @param int $iOidOutputFormat OID output format, defaults to numeric
	 * @return SNMP
	 */
	protected static function LoadSNMPConnection(string $sHostname, SnmpCredentials $oCredentials, int $iOidOutputFormat = SNMP_OID_OUTPUT_NUMERIC): SNMP
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
		$oSNMP->oid_output_format = $iOidOutputFormat;
		
		return $oSNMP;
	}

    /**
     * Process contact list to lookup existing contacts
     * @param array $aLineData
     * @param int $iLineIndex
     * @param string $sDestField
     * @throws Exception
     */
	protected static function ProcessContactsLookup(array &$aLineData, int $iLineIndex, string $sDestField): void
	{
		static $iDestFieldPos = 0;

		if ($iLineIndex === 0) {
			foreach ($aLineData as $idx => $sHeader) if ($sHeader === $sDestField) {
				$iDestFieldPos = $idx;
			}
			return;
		}

		$oClient = new RestClient();
		$aLookupContacts = json_decode($aLineData[$iDestFieldPos]);
		$aContacts = [];

		foreach ($aLookupContacts as $aKeySpec) {
			$sKeySpecHash = md5(serialize($aKeySpec));
			if (!array_key_exists($sKeySpecHash, static::$aLookupContacts)) {
				try {
					$aFoundContacts = [];
					$aResults = $oClient->Get('Contact', $aKeySpec);
					if ($aResults['code'] != 0) {
						Utils::Log(LOG_ERR, $aResults['message']);
						continue;
					} elseif (!empty($aResults['objects'])) foreach ($aResults['objects'] as $aContact) {
						$aFoundContacts[] = sprintf('contact_id:%d', $aContact['key']);
					} else {
						Utils::Log(LOG_WARNING, sprintf('Could not retrieve contact information for %s', json_encode($aKeySpec)));
					}
					static::$aLookupContacts[$sKeySpecHash] = $aFoundContacts;
					$aContacts += $aFoundContacts;
				} catch (Exception $e) {
					Utils::Log(LOG_ERR, $e->getMessage());
				}
			} else {
				$aContacts += static::$aLookupContacts[$sKeySpecHash];
			}
		}
		$aLineData[$iDestFieldPos] = implode('|', array_unique($aContacts));
	}
}
