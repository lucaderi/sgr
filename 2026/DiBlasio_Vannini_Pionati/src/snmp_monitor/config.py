import yaml

from snmp_monitor.models import AgentConfig

def leggi_config(path: str) -> list[AgentConfig]:
    """
    Legge il contenuto yaml del file di configurazione e restituisce una lista di oggetti AgentConfig.
    """

    with open(path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    
    agents = []
    
    for agent in config["agents"]:
        agent = AgentConfig(
            name = agent["name"],
            host = agent["host"],
            community = agent["community"],
            port = agent["port"],
        )
        agents.append(agent)
        
    return agents