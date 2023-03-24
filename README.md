# Octavia Provider Driver for F5 BigIP devices

This is the [Octavia](https://github.com/sapcc/octavia) provider driver for F5 BigIP appliances.
It communicates with BigIP devices via the declarative [AS3 API](https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/).
The worker uses the driver-agent API, but it hooks more deeply into Octavia (similar to the Octavia Amphora driver) than the [Provider Agents concept](https://docs.openstack.org/octavia/latest/contributor/guides/providers.html) permits, e.&nbsp;g. by accessing the database directly.


# Modules
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

# Special database handling
This provider driver uses Octavias mariadb database to store some data, but doesn't define any new tables.
Instead, otherwise unused tables are used in a specific way:
- The **amphora** table is used in two ways:
  - For each load balancer an amphora entry is created. This is done [to prevent problems with Octavias health manager](./octavia_f5/controller/worker/controller_worker.py#L249-L251), which makes assumptions about amphora entries.
    - `compute_flavor` holds the name of the device the load balancer is scheduled to. This can be used to query the device via `openstack loadbalancer amphora show $LB_ID`.
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

# F5-specific configuration options
There are lots of F5-specific configuration options. They can be found in `octavia_f5/common/config.py`.
- If `agent_scheduler` in the `[networking]` section of the configuration is set to `loadbalancer`, new load balancers are scheduled to the device with the least load balancers. This is the default. If it is set to `listener`, new load balancers are scheduled to the device with the least listeners.

# Listener type to AS3 service class mapping
Mapping happens in [`octavia_f5/restclient/as3objects/service.py`](./octavia_f5/restclient/as3objects/service.py).
| Openstack listener type | AS3 service class |
|-|-|
| TCP | Service_L4 |
| UDP | Service_UDP |
| HTTP | Service_HTTP |
| HTTPS | Service_L4 |
| PROXY | Service_TCP |
| TERMINATED_HTTPS | Service_HTTPS |
