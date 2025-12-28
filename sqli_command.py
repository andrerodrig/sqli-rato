import aiohttp


class SqliCommand:

    URI_PATTERN = (
        r"^(?P<scheme>(http|https)?)://(?P<host>[^/:]+)(:(?P<port>\d+))?(?P<path>/.*)?$"
    )

    def __init__(self, uri_path, cookie: str | None, db: str | None) -> None:
        """
        SQLi Command class that hendles the parameters of SQL injection.

        :param uri_path: Target URI path with injected code.
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
        match = self.URL_REGEX.match(self._uri_path)

        if not match:
            raise ValueError(f"Invalid URI format: {self._uri_path}")

        self._scheme = match.group("scheme")
        self._host = match.group("host")
        self._port = int(match.group("port")) if match.group("port") else None
        self._path = match.group("path") or "/"

    @property
    def base_url(self) -> str:
        if self._port:
            return f"{self._scheme}://{self._host}:{self._port}"
        return f"{self._scheme}://{self._host}"

    @property
    def full_url(self) -> str:
        return f"{self.base_url}{self._path}"

    def _build_headers(self) -> dict[str, str]:
        headers = {}
        # headers = {
        #     "User-Agent": "SQLi-CLI/0.1",
        # }

        if self._cookie:
            headers["Cookie"] = self._cookie

        return headers

    async def send_get(self, timeout: int = 10) -> aiohttp.ClientResponse:
        async with aiohttp.ClientSession(
            headers=self._build_headers()
        ) as session:
            async with session.get(
                self.full_url,
                timeout=timeout
            ) as response:
                await response.read()
                return response

    async def send_post(
        self,
        data: dict[str, str],
        timeout: int = 10
    ) -> aiohttp.ClientResponse:
        async with aiohttp.ClientSession(
            headers=self._build_headers()
        ) as session:
            async with session.post(
                self.full_url,
                data=data,
                timeout=timeout
            ) as response:
                await response.read()
                return response


if __name__ == "__main__":
    sqli_command = SqliCommand("")