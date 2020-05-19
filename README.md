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
- `db`: Repository classes, scripts for migration from Neutron to Octavia
- `network`: Layer 2 network drivers (Neutron hierarchical port binding driver, no-op driver)
- `restclient`: Classes for building AS3 declarations. Used by `sync_manager` and `status_manager`.


# F5-specific configuration options
There are lots of F5-specific configuration options. They can be found in `octavia_f5/common/config.py`.
