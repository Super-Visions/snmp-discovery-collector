<?php

class VirtualInterfaceCollector extends SnmpInterfaceCollector
{
	/**
	 * Retrieve and prepare interfaces discovered by SnmpDiscoveryCollector
	 * @return true
	 */
	public function Prepare()
	{
		$this->aInterfaces = SnmpDiscoveryCollector::$aDiscoveredInterfaces['networkdevicevirtualinterfaces_list'];

		return parent::Prepare();
	}

	/**
	 * Do actual device lookup
	 * @inheritDoc
	 */
	public function ProcessLineBeforeSynchro(&$aLineData, $iLineIndex)
	{
		$this->oDeviceLookup->Lookup($aLineData, static::DeviceLookupFields, 'networkdevice_id', $iLineIndex);
		parent::ProcessLineBeforeSynchro($aLineData, $iLineIndex);
	}
}
