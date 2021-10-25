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
  - For each load balancer an amphora entry is created. This is done to prevent problems with Octavias health manager, which makes assumptions about amphora entries.
  - For each F5 device that is managed by a provider driver worker a special entry is created in the `amphora` table. Here, `load_balancer_id` will always be null, `compute_flavor` contains the name of the managed F5 device, `cached_zone` its hostname, and `vrrp_priority` the amount of listeners on that device.
	`status` is set to `ALLOCATED` if the device is offline (no entry in device status response), `READY` if it is online, or `BOOTING` if it was offline and is now back online. In the latter case the device receives a full sync and the status is set to `READY`.

# F5-specific configuration options
There are lots of F5-specific configuration options. They can be found in `octavia_f5/common/config.py`.
- If `agent_scheduler` in the `[networking]` section of the configuration is set to `loadbalancer`, new load balancers are scheduled to the device with the least load balancers. This is the default. If it is set to `listener`, new load balancers are scheduled to the device with the least listeners.
