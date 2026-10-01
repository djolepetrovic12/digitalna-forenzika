from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

def extract_system_fields(root: ET.Element) -> dict[str, Any]:
    system = root.find(".//{*}System")
    if system is None:
        return {}

    data: dict[str, Any] = {}
    provider_node = system.find("{*}Provider")
    if provider_node is not None:
        data["Provider"] = {"Name": provider_node.attrib.get("Name")}

    correlation_node = system.find("{*}Correlation")
    if correlation_node is not None:
        data["Correlation"] = {k: v for k, v in correlation_node.attrib.items() if v is not None}

    for field in ("EventID", "Version", "Computer", "Level", "Channel", "EventRecordID"):
        node = system.find(f"{{*}}{field}")
        if node is not None:
            data[field] = node.text

    time_node = system.find("{*}TimeCreated")
    if time_node is not None:
        data["TimeCreated"] = time_node.attrib.get("SystemTime")

    return data


def extract_event_data(root: ET.Element) -> dict[str, Any]:
    event_data: dict[str, Any] = {}
    for node in root.findall(".//{*}EventData/{*}Data"):
        key = node.attrib.get("Name")
        if key is None:
            continue
        event_data[key] = node.text

    return event_data


def extract_user_data(root: ET.Element) -> dict[str, Any]:
    user_data: dict[str, Any] = {}
    for node in root.findall(".//{*}UserData"):
        for child in list(node):
            user_data[child.tag.split("}")[-1]] = child.text
    return user_data


def extract_generic_fields(xml_text: str) -> dict[str, Any]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return {}

    system = extract_system_fields(root)
    event_data = extract_event_data(root)
    user_data = extract_user_data(root)

    return {
        "system": system,
        "event_data": event_data,
        "user_data": user_data,
    }
