# Source Layout

`attack/` contains the DHCP starvation traffic generator. Attacks can be
launched either with the custom Python script in this directory or with
Yersinia. Yersinia is a well-known external network attack/testing tool, but it
offers less scenario-level customization than the custom Python attack script.
It is included to show that the detector also resists real external-tool
attacks, not only ad hoc scenarios tailored around the custom script.

`defense/` contains the DHCP starvation detector and mitigation code, including
the detector core, configuration, whitelist/reputation logic, RRD stats, and
NETCONF router-control actions.
