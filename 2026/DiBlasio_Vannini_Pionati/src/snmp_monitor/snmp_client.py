from pysnmp.hlapi.asyncio import (
    bulk_walk_cmd,
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
)

snmpEngine = SnmpEngine() # Integra tutta la logica necessaria per inviare e ricevere messaggi SNMP


async def snmp_bulk_walk(host: str, port: int, community: str, oid: str, timeout: float = 2.0, retries: int = 1, maxRep: int = 20) -> dict[int, str]:
    risultati: dict[int, str] = {}

    communicationChannel = await UdpTransportTarget.create((host, port), timeout, retries) # Contiene IP, porta, protocollo utilizzato

    # varBinds contiene la coppia (OID, valore)
    async for errorIndication, errorStatus, errorIndex, varBinds in bulk_walk_cmd(
        snmpEngine, 
        CommunityData(community, mpModel = 1), # Serve per autenticarsi, mpModel specifica il protocollo (SNMPv2c in questo caso)
        communicationChannel, 
        ContextData(),
        0,                              # nonRepeaters: indica che le variabili verranno lette con la parte "bulk"
        maxRep,                         # maxRepetitions: per ogni richiesta restituisce maxRep valori
        ObjectType(ObjectIdentity(oid)), # Trasforma l'oggetto OID passato in una richiesta SNMP
        lexicographicMode=False, # Con questo parametro indico alla walk di fermarsi quando finisce il sottoalbero
        lookupMib=False, # Non effettua traduzioni 
    ):
        if errorIndication:
            raise RuntimeError(f"[{host}] SNMP error: {errorIndication}")

        if errorStatus:
            raise RuntimeError(
                f"[{host}] SNMP error: {errorStatus.prettyPrint()} "
                f"at index {errorIndex}"
            )
    
        # Estrae da varBinds (OID, valore) rimuove il prefisso e lo associa al valore
        for oidResponse, value in varBinds:
            oidResponse = str(oidResponse)

            if not oidResponse.startswith(oid + "."):
                continue

            idx = int(oidResponse.removeprefix(oid + "."))
            risultati[idx] = value.prettyPrint()

    return risultati