# Octavia Provider Driver for F5 BigIP devices

This is the [Octavia](https://github.com/sapcc/octavia) provider driver for F5 BigIP appliances.
It communicates with BigIP devices via the declarative [AS3 API](https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/).
The worker uses the driver-agent API, but it hooks more deeply into Octavia (similar to the Octavia Amphora driver) than the [Provider Agents concept](https://docs.openstack.org/octavia/latest/contributor/guides/providers.html) permits, e.&nbsp;g. by accessing the database directly.


## F5-specific configuration

### Naming conventions
Some naming conventions are a bit different between the F5 provider driver and the BigIP devices it can provision. This is partly due to the fact that naming conventions changed between i-Series BigIP vCMP host devices and the newer r-Series BigIP vCMP host devices. E.&nbsp;g. in the i-Series, the term *tenant* is used to refer to partitions within vCMP guests (this provider driver maps one Neutron network to one such partition), so we use that term in the code as well. In the r-Series however the term *tenant* is also used to refer to a whole vCMP guest. To avoid confusion, we keep the old i-Series naming conventions.

### F5-specific config options
There are lots of F5-specific configuration options. They can be found in `octavia_f5/common/config.py`.
- If `agent_scheduler` in the `[networking]` section of the configuration is set to `loadbalancer`, new load balancers are scheduled to the device with the least amount of load balancers. This is the default. If it is set to `listener`, new load balancers are scheduled to the device with the least amount of listeners.

### Listener type to AS3 service class mapping
Mapping happens in [`octavia_f5/restclient/as3objects/service.py`](./octavia_f5/restclient/as3objects/service.py).
| Openstack listener type | AS3 service class | Notes |
|-|-|-|
| TCP | Service_L4 | Uses L4 acceleration |
| UDP | Service_UDP | |
| HTTP | Service_HTTP | |
| HTTPS | Service_L4 | Uses L4 acceleration, since HTTPS simply gets passed through without decryption |
| PROXY | Service_TCP | Does *not* use L4 acceleration, since it's incompatible with the Proxy Protocol iRule |
| TERMINATED_HTTPS | Service_HTTPS | |

### Health monitor configuration mapping
Since health monitors have different semantics in Octavia than on the BigIP (and inconsistent naming across API and database), we have to map Octavia health monitor parameters to AS3/BigIP parameters in a specific way.
We try to name the parameters on the Elektra web GUI in an explanatory way.
| Elektra web GUI | CLI/API          | database       | AS3/BigIP  |
|-----------------|------------------|----------------|------------|
|                 | max_retries      | rise_threshold |            |
| Max Retries[1]  | max_retries_down | fall_threshold | timeout[2] |
| Probe Timeout   | timeout          | timeout        |            |
| Interval        | delay            | delay          | interval   |

[1] [Original Elektra PR](https://github.com/sapcc/elektra/pull/1175) superseeded by [new Elektra PR](https://github.com/sapcc/elektra/pull/1179) which has been merged

[2] Calculated from database parameters like this: `fall_threshold * delay + 1` (see [code](https://github.com/sapcc/octavia-f5-provider-driver/blob/stable/2025.1-m3/octavia_f5/restclient/as3objects/monitor.py#L110-L119))


## Special database handling
This provider driver uses Octavias mariadb database to store some data, but doesn't define any new tables.
Instead, otherwise unused tables/columns are used in a specific way:
- The **load_balancer** table is used like this:
  - `server_group_id` holds the name of the device the load balancer is scheduled to. Compare with `compute_flavor` in the `amphora` table below. Note that `server_group_id` is not shown by the CLI when running `openstack loadbalancer show`.
- The **amphora** table is used in two ways:
  - For each load balancer an amphora entry is created. This is done [to prevent problems with Octavias health manager](./octavia_f5/controller/worker/controller_worker.py#L251-L253), which makes assumptions about amphora entries.
    - `compute_flavor` holds the name of the device the load balancer is scheduled to. Compare with `server_group_id` in the `load_balancer` table above. This can be used to query the device via `openstack loadbalancer amphora show $LB_ID`.
    - Since an amphora table entry is never updated as long as its respective load balancer lives, the `updated_at` field will always be `null` until the load balancer is being deleted, [which will update the amphora entry status to `DELETED` as well](octavia_f5/controller/worker/status_manager.py#L158).
  - For each F5 device that is managed by a provider driver worker a special entry is created in the `amphora` table.
    - `compute_flavor` holds the name of the managed F5 device
    - `cached_zone` holds the hostname
    - `load_balancer_id` will always be null
    - `role` (must contain one of the values defined in the `amphora_roles` table) holds information about whether the device is in active status (`MASTER`) or standby status (`BACKUP`)
    - `status` (must contain one of the values defined in the `provisioning_status` table) holds device state.
      - `ALLOCATED` means the the device is offline (no entry in device status response)
      - `READY` means the device is online
      - `BOOTING` if it was offline and is now back online. In this case the device receives a full sync and the status is set to `READY`.
    - If `vrrp_interface` is set to 'disabled' for a given F5 amphora entry, the [scheduler](./octavia_f5/db/scheduler.py#L53) will not take that device into account when scheduling new load balancers.
    - `vrrp_priority` holds the amount of listeners on that device


## Python modules
- `octavia_f5/api`: Driver, running in Octavia main process (extends [`AmphoraProviderDriver`](https://github.com/sapcc/octavia/blob/stable/stein-m3/octavia/api/drivers/amphora_driver/driver.py#L42))
- `octavia_f5/cmd`: Entry points for house-keeping and status manager.
  - `house_keeping`: DB cleanup. Uses Octavia class [`DatabaseCleanup`](https://github.com/sapcc/octavia/blob/stable/stein-m3/octavia/controller/housekeeping/house_keeping.py#L80)
- `octavia_f5/controller`: Communication with BigIP device
  - `status_manager`: Manages table entries representing BigIP devices
  - `controller_worker`: REST endpoints for Octavia, synchronization loop
  - `sync_manager`: Builds AS3 declarations and sends them to the BigIP device.
  - `status`: Methods for setting status in database. Used by `controller_worker`.
- `db`: Repository classes (CRUD abstractions over sqlalchemy ORM objects)
- `network`: Layer 2 network drivers (Neutron hierarchical port binding driver, no-op driver)
- `restclient`: Classes for building AS3 declarations. Used by `sync_manager` and `status_manager`.
