import functools
import aiohttp
import logging
import uuid

from src import CF_API_TOKEN, CF_IDENTIFIER


def aiohttp_session(func):
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=20),
            headers={"Authorization": f"Bearer {CF_API_TOKEN}"},
        ) as session:
            kwargs["session"] = session
            return await func(*args, **kwargs)

    return wrapper


@aiohttp_session
async def get_lists(name_prefix: str, session: aiohttp.ClientSession):
    async with session.get(
        f"https://api.cloudflare.com/client/v4/accounts/{CF_IDENTIFIER}/gateway/lists",
    ) as resp:
        resp_json = await resp.json()
        if not resp_json["success"]:
            logging.error(resp_json)
            raise Exception("Failed to get Cloudflare lists")

        lists = resp_json["result"] or []
        return [l for l in lists if l["name"].startswith(name_prefix)]


@aiohttp_session
async def get_items(uuid: uuid, pages: int, session: aiohttp.ClientSession):
    item_values = []
    for i in range(1, pages + 1):  # for exclusive
        async with session.get(
            f"https://api.cloudflare.com/client/v4/accounts/{CF_IDENTIFIER}/gateway/lists/{uuid}/items?page={i}",
        ) as resp:
            resp_json = await resp.json()
            if resp.status != 200:
                logging.error(resp_json)
                raise Exception("Failed to get Cloudflare list items")
            items = [j["vaule"] for j in resp_json["result"]]
            item_values.append(items)
    return item_values


@aiohttp_session
async def create_list(name: str, domains: list[str], session: aiohttp.ClientSession):
    async with session.post(
        f"https://api.cloudflare.com/client/v4/accounts/{CF_IDENTIFIER}/gateway/lists",
        json={
            "name": name,
            "description": "Created by script.",
            "type": "DOMAIN",
            "items": [{"value": d} for d in domains],
        },
    ) as resp:
        if resp.status != 200:
            raise Exception("Failed to create Cloudflare list")

        return (await resp.json())["result"]


@aiohttp_session
async def patch_list(uuid: uuid, domains: list[str], session: aiohttp.ClientSession):
    async with session.patch(
        f"https://api.cloudflare.com/client/v4/accounts/{CF_IDENTIFIER}/gateway/lists/{uuid}",
        json={
            "items": [{"value": d} for d in domains],
        },
    ) as resp:
        if resp.status != 200:
            raise Exception("Failed to create Cloudflare list")

        return (await resp.json())["result"]


@aiohttp_session
async def delete_list(name: str, list_id: str, session: aiohttp.ClientSession):
    async with session.delete(
        f"https://api.cloudflare.com/client/v4/accounts/{CF_IDENTIFIER}/gateway/lists/{list_id}",
    ) as resp:
        if resp.status != 200:
            logging.error(resp)
            raise Exception("Failed to delete Cloudflare list")

        return (await resp.json())["result"]


@aiohttp_session
async def get_firewall_policies(name_prefix: str, session: aiohttp.ClientSession):
    async with session.get(
        f"https://api.cloudflare.com/client/v4/accounts/{CF_IDENTIFIER}/gateway/rules",
    ) as resp:
        if resp.status != 200:
            raise Exception("Failed to get Cloudflare firewall policies")

        policies = (await resp.json())["result"] or []
        return [l for l in policies if l["name"].startswith(name_prefix)]


@aiohttp_session
async def create_gateway_policy(
    name: str, list_ids: list[str], session: aiohttp.ClientSession
):
    async with session.post(
        f"https://api.cloudflare.com/client/v4/accounts/{CF_IDENTIFIER}/gateway/rules",
        json={
            "name": name,
            "description": "Created by script.",
            "action": "block",
            "enabled": True,
            "filters": ["dns"],
            "traffic": "or".join([f"any(dns.domains[*] in ${l})" for l in list_ids]),
            "rule_settings": {
                "block_page_enabled": False,
            },
        },
    ) as resp:
        if resp.status != 200:
            raise Exception("Failed to create Cloudflare firewall policy")
        return (await resp.json())["result"]


@aiohttp_session
async def update_gateway_policy(
    name: str, policy_id: str, list_ids: list[str], session: aiohttp.ClientSession
):
    async with session.put(
        f"https://api.cloudflare.com/client/v4/accounts/{CF_IDENTIFIER}/gateway/rules/{policy_id}",
        json={
            "name": name,
            "action": "block",
            "enabled": True,
            "traffic": "or".join([f"any(dns.domains[*] in ${l})" for l in list_ids]),
        },
    ) as resp:
        if resp.status != 200:
            raise Exception("Failed to update Cloudflare firewall policy")

        return (await resp.json())["result"]


@aiohttp_session
async def delete_gateway_policy(
    policy_name_prefix: str, session: aiohttp.ClientSession
):
    async with session.get(
        f"https://api.cloudflare.com/client/v4/accounts/{CF_IDENTIFIER}/gateway/rules",
    ) as resp:
        if resp.status != 200:
            raise Exception("Failed to get Cloudflare firewall policies")

        policies = (await resp.json())["result"] or []
        policy_to_delete = next(
            (p for p in policies if p["name"].startswith(policy_name_prefix)), None
        )

        if not policy_to_delete:
            return 0

        policy_id = policy_to_delete["id"]

    async with session.delete(
        f"https://api.cloudflare.com/client/v4/accounts/{CF_IDENTIFIER}/gateway/rules/{policy_id}",
    ) as resp:
        if resp.status != 200:
            raise Exception("Failed to delete Cloudflare gateway firewall policy")

        return 1
