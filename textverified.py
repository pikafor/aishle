"""Клиент TextVerified API v2 — только то, что нам нужно:
- аутентификация (bearer-токен с автообновлением)
- список SMS сообщений для rental-номеров по номеру телефона
"""
from __future__ import annotations

import time
import threading
from typing import Any, Dict, List, Optional

import requests

API_BASE = "https://www.textverified.com/api/pub/v2"
TOKEN_TTL_SAFETY = 60  # обновляем токен за минуту до истечения


class TextVerifiedError(Exception):
    """Любая ошибка API TextVerified с человекочитаемым описанием."""


class TextVerifiedClient:
    """Простой синхронный клиент: один инстанс = один набор кредов.

    Аутентификация (по документации v2):
        POST /api/pub/v2/auth
        Headers: X-API-KEY + X-API-USERNAME
        Ответ:   { token, expiresIn, expiresAt }

    Если username не задан — пробуем legacy-эндпоинт
    POST /api/SimpleAuthentication с заголовком x-simple-api-access-token
    (достаточно одного API-ключа).
    """

    def __init__(self, api_username: str = "", api_key: str = "", base_url: str = API_BASE):
        if not api_key:
            raise TextVerifiedError("Не задан API-ключ TextVerified")
        self.api_username = api_username
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._lock = threading.Lock()

    # -------- auth --------
    def _authenticate(self) -> None:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-API-KEY"] = self.api_key
        if self.api_username:
            headers["X-API-USERNAME"] = self.api_username

        last_err: Optional[Exception] = None
        # 1) v2: заголовки X-API-KEY / X-API-USERNAME
        try:
            r = requests.post(f"{self.base_url}/auth", headers=headers, timeout=15)
            if r.status_code < 400:
                self._parse_token(r.json(), legacy=False)
                return
            if r.status_code in (400, 401, 403):
                last_err = TextVerifiedError(f"Auth v2 {r.status_code}: {self._err_text(r)}")
            else:
                last_err = TextVerifiedError(f"Auth v2 {r.status_code}: {self._err_text(r)}")
        except requests.RequestException as e:
            last_err = TextVerifiedError(f"Сеть (auth v2): {e}")

        # 2) legacy: только API-ключ (тот же хост, путь /api/SimpleAuthentication)
        if not self.api_username:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(self.base_url)
            legacy_url = urlunparse((parsed.scheme, parsed.netloc,
                                     "/api/SimpleAuthentication", "", "", ""))
            try:
                r = requests.post(
                    legacy_url,
                    headers={"x-simple-api-access-token": self.api_key,
                             "Content-Type": "application/json", "Accept": "application/json"},
                    timeout=15,
                )
                if r.status_code < 400:
                    self._parse_token(r.json(), legacy=True)
                    return
                last_err = TextVerifiedError(f"Auth legacy {r.status_code}: {self._err_text(r)}")
            except requests.RequestException as e:
                last_err = TextVerifiedError(f"Сеть (auth legacy): {e}")

        raise TextVerifiedError(str(last_err) or "Auth: неизвестная ошибка")

    def _parse_token(self, data: Dict[str, Any], legacy: bool) -> None:
        # v2: { token, expiresIn, expiresAt }   legacy: { bearer_token, expiration, ticks }
        token = data.get("token") or data.get("bearer_token") or data.get("access_token")
        if not token:
            raise TextVerifiedError(f"Auth: нет токена в ответе: {data}")
        self._token = token
        expires_in = data.get("expiresIn") or data.get("expires_in") or data.get("ticks") or 1800
        try:
            expires_in = float(expires_in)
        except (TypeError, ValueError):
            expires_in = 1800.0
        if expires_in <= 0:
            expires_in = 1800.0
        self._token_expires_at = time.time() + expires_in - TOKEN_TTL_SAFETY

    def _get_token(self) -> str:
        with self._lock:
            if not self._token or time.time() >= self._token_expires_at:
                self._authenticate()
            assert self._token
            return self._token

    # -------- HTTP --------
    def _request(self, method: str, path: str, params: Optional[dict] = None) -> Dict[str, Any]:
        token = self._get_token()
        # path может быть как путём ('/sms'), так и полным URL из links.next
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        try:
            r = requests.request(method, url, headers=headers, params=params, timeout=20)
        except requests.RequestException as e:
            raise TextVerifiedError(f"Сеть: {e}") from e

        # при 401 пробуем обновить токен один раз
        if r.status_code == 401:
            with self._lock:
                self._authenticate()
            headers["Authorization"] = f"Bearer {self._token}"
            try:
                r = requests.request(method, url, headers=headers, params=params, timeout=20)
            except requests.RequestException as e:
                raise TextVerifiedError(f"Сеть: {e}") from e

        if r.status_code >= 400:
            raise TextVerifiedError(f"{method} {path} → {r.status_code}: {self._err_text(r)}")
        try:
            return r.json()
        except ValueError as e:
            raise TextVerifiedError(f"Невалидный JSON: {e}") from e

    @staticmethod
    def _err_text(r: requests.Response) -> str:
        try:
            j = r.json()
            return j.get("message") or j.get("error") or j.get("errorMessage") or r.text[:300]
        except ValueError:
            return (r.text or "")[:300]

    # -------- public API --------
    def list_sms(
        self,
        to: Optional[str] = None,
        reservation_type: Optional[str] = None,
        reservation_id: Optional[str] = None,
        limit: int = 100,
        max_pages: int = 10,
    ) -> List[Dict[str, Any]]:
        """GET /api/pub/v2/sms с пагинацией.

        По документации:
          ?to=<номер>            — фильтр по номеру
          ?reservationId=<id>    — фильтр по резервации
          ?reservationType=renewable|nonrenewable|verification

        Ответ: { data: [ {id, from, to, createdAt, smsContent, parsedCode, encrypted} ],
                 hasNext, hasPrevious, count, links: {current, previous, next} }
        """
        params: Dict[str, Any] = {"limit": limit}
        if to:
            params["to"] = to
        if reservation_type:
            params["reservationType"] = reservation_type
        if reservation_id:
            params["reservationId"] = reservation_id

        all_items: List[Dict[str, Any]] = []
        next_href: Optional[str] = None
        for _ in range(max_pages):
            if next_href:
                # следующая страница приходит полным URL (с собственным query-string)
                payload = self._request("GET", next_href)
            else:
                payload = self._request("GET", "/sms", params=params)

            data = payload.get("data", payload)
            if isinstance(data, list):
                all_items.extend(data)
            elif isinstance(data, dict) and "items" in data:
                all_items.extend(data["items"])

            links = payload.get("links") or {}
            nxt = links.get("next")
            if nxt and isinstance(nxt, dict) and nxt.get("href"):
                next_href = nxt["href"]
            else:
                break
        return all_items

    def get_rental_sms_by_phone(self, phone: str) -> Dict[str, List[Dict[str, Any]]]:
        """Возвращает SMS для номера, сгруппированные по типу rental.

        Если оба типа упали (например, неверные креды) — поднимается
        TextVerifiedError, чтобы UI показал ошибку, а не пустой список.
        """
        result: Dict[str, List[Dict[str, Any]]] = {"renewable": [], "nonrenewable": []}
        errors: List[str] = []
        for rtype in ("renewable", "nonrenewable"):
            try:
                result[rtype] = self.list_sms(to=phone, reservation_type=rtype)
            except TextVerifiedError as e:
                result[rtype] = []
                errors.append(str(e))
        if not result["renewable"] and not result["nonrenewable"] and errors:
            raise TextVerifiedError(errors[0])
        return result


# -------- singleton helpers --------
_client: Optional[TextVerifiedClient] = None
_client_lock = threading.Lock()


def get_client(api_username: Optional[str] = None, api_key: Optional[str] = None) -> TextVerifiedClient:
    """Возвращает (или пересоздаёт) клиент по переданным кредам."""
    global _client
    with _client_lock:
        if _client is None or api_username != _client.api_username or api_key != _client.api_key:
            _client = TextVerifiedClient(api_username or "", api_key or "")
        return _client


def reset_client() -> None:
    """Сбрасывает кэшированный клиент (например, после смены кредов в админке)."""
    global _client
    with _client_lock:
        _client = None