# Octavia Provider Driver for F5 BigIP LTM devices

This is the [Octavia](https://github.com/sapcc/octavia) provider driver for F5 BigIP LTM appliances.
It communicates with BigIP devices via the declarative [AS3 API](https://clouddocs.f5.com/products/extensions/f5-appsvcs-extension/latest/).

Note: What we call 'worker' is called 'provider agent' in the [Octavia Provider Driver Development Guide](https://docs.openstack.org/octavia/latest/contributor/guides/providers.html).

# Entrypoints
All scripts are called with the following parameters: `--debug --config-file ~/.config/octavia.conf`
All scripts are called with the following environment variables: `PYTHONUNBUFFERED=1;PYTHONWARNINGS=ignore:Unverified HTTPS request`

| Component | Project | Module name |
|-|-|-|
| Octavia API | octavia | `octavia.cmd.api:main` |
| Octavia driver agent | octavia | `octavia.cmd.driver_agent:main` |
| Octavia worker | octavia-f5-provider-driver | `octavia.cmd.octavia_worker:main` |
| Octavia house-keeping | octavia-f5-provider-driver | `octavia_f5.cmd.house_keeping:main` |
| Octavia status manager | octavia-f5-provider-driver | `octavia_f5.cmd.status_manager:main` |

# Modules
- `octavia_f5/api`: Driver, running in Octavia main process (extends [`AmphoraProviderDriver`](https://github.com/sapcc/octavia/blob/stable/stein-m3/octavia/api/drivers/amphora_driver/driver.py#L42))
- `octavia_f5/cmd`: Entry points for house-keeping and status manager.
  - `house_keeping`: DB cleanup. Uses Octavia class [`DatabaseCleanup`](https://github.com/sapcc/octavia/blob/stable/stein-m3/octavia/controller/housekeeping/house_keeping.py#L80)
- `octavia_f5/controller`: Communication with BigIP device
  - `status_manager`: Manages table entries representing BigIP devices
  - `controller_worker`: REST endpoints for Octavia, synchronization loop
  - `f5agent_driver`: Builds AS3 declarations and sends them to the BigIP device.
  - `status`: Methods for setting status in database. Used by `controller_worker`.
- `db`: Repository classes, scripts for migration from Neutron to Octavia
- `network`: Layer 2 network drivers (Neutron hierarchical port binding driver, no-op driver)
- `restclient`: Classes for building AS3 declarations. Used by `f5agent_driver` and `status_manager`.