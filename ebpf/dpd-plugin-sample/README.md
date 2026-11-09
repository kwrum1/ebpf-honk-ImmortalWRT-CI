# dpd-plugin-sample

Reference implementation of the `dpdfwd` plugin ABI (v1). See
`docs/PLUGIN-ABI.md` for the contract.

- exports `struct dpd_plugin_ops dpd_plugin_ops`;
- `flow_classify` blocks TCP/25 (dpdfwd writes it into `dpd_class`);
- `flow_create` / `flow_expire` / `topology_event` count events;
- `dump` returns a one-line state string.

Build as a normal OpenWrt package:

```sh
make package/dpd-plugin-sample/compile
```

The `.so` lands in `/usr/lib/dpd/plugins/`; `dpdfwd` loads it on start.
A plugin failure only skips that plugin; the packet path is unaffected.
