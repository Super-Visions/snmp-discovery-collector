<?php
/**
 * @copyright Copyright (C) 2023 Super-Visions
 * @license http://opensource.org/licenses/AGPL-3.0
 * @noinspection PhpUnhandledExceptionInspection
 */

require_once(__DIR__.'/src/SnmpCredentials.class.inc.php');
require_once(__DIR__.'/src/SnmpDiscoveryCollector.class.inc.php');

Orchestrator::AddRequirement('8.1');
Orchestrator::AddRequirement('8.1', 'snmp');
Orchestrator::AddCollector(1, SnmpDiscoveryCollector::class);
