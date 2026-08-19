"""Клиент TextVerified API v2 — только то, что нам нужно:
- аутентификация (bearer-токен с автообновлением)
- список SMS сообщений для rental-номеров по номеру телефона
"""
from __future__ import annotations

import time
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

API_BASE = "https://www.textverified.com/api/pub/v2"
TOKEN_TTL_SAFETY = 60  # обновляем токен за минуту до истечения


class TextVerifiedError(Exception):
    """Любая ошибка API TextVerified с человекочитаемым описанием."""


class TextVerifiedClient:
    """Простой синхронный клиент: один инстанс = один набор кредов."""

    def __init__(self, api_username: str, api_key: str, base_url: str = API_BASE):
        if not api_username or not api_key:
            raise TextVerifiedError("Не заданы apiUsername или apiKey")
        self.api_username = api_username
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._lock = threading.Lock()

    # -------- auth --------
    def _authenticate(self) -> None:
        """POST /api/pub/v2/auth -> { bearer_token, expires_in, ... }"""
        url = f"{self.base_url}/auth"
        try:
            r = requests.post(
                url,
                json={"apiUsername": self.api_username, "apiKey": self.api_key},
                timeout=15,
            )
        except requests.RequestException as e:
            raise TextVerifiedError(f"Сеть: {e}") from e

        if r.status_code >= 400:
            raise TextVerifiedError(f"Auth {r.status_code}: {self._err_text(r)}")
        data = r.json()
        token = data.get("bearer_token") or data.get("access_token") or data.get("token")
        if not token:
            raise TextVerifiedError(f"Auth: нет bearer_token в ответе: {data}")
        self._token = token
        # expires_in — секунды; запас прочности
        self._token_expires_at = time.time() + float(data.get("expires_in", 1800)) - TOKEN_TTL_SAFETY

    def _get_token(self) -> str:
        with self._lock:
            if not self._token or time.time() >= self._token_expires_at:
                self._authenticate()
            assert self._token
            return self._token

    # -------- HTTP --------
    def _request(self, method: str, path: str, params: Optional[dict] = None) -> Dict[str, Any]:
        token = self._get_token()
        url = f"{self.base_url}{path}"
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
        to_number: Optional[str] = None,
        reservation_type: Optional[str] = None,
        reservation_id: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
        max_pages: int = 10,
    ) -> List[Dict[str, Any]]:
        """Получает историю SMS, аналог ``client.sms.incoming(..., since=...)``.

        В отличие от ``incoming`` из официального SDK этот метод не ждёт новые
        сообщения: он читает уже сохранённую историю через v2 API. Фильтр
        ``since`` также применяется локально, поэтому история не зависит от
        того, поддерживает ли конкретная версия API параметр ``since``.
        """
        params: Dict[str, Any] = {"limit": limit}
        if to_number:
            params["to_number"] = to_number
        if reservation_type:
            params["reservationType"] = reservation_type
        if reservation_id:
            params["reservationId"] = reservation_id

        all_items: List[Dict[str, Any]] = []
        next_href: Optional[str] = None
        for _ in range(max_pages):
            if next_href:
                # следующая страница приходит полным href
                # она может уже содержать query-string
                from urllib.parse import urlparse, parse_qs
                p = urlparse(next_href)
                # собираем новые params, перебивая предыдущие
                page_params = {k: v[0] for k, v in parse_qs(p.query).items()}
                payload = self._request("GET", p.path, params=page_params)
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

        if since is None:
            return all_items

        # API может отдавать createdAt/receivedAt в разных форматах. Не
        # отбрасываем сообщение, если дата неизвестна: лучше показать его,
        # чем потерять код из-за различий версий API.
        since_utc = since.astimezone(timezone.utc) if since.tzinfo else since.replace(tzinfo=timezone.utc)
        return [item for item in all_items if self._message_is_since(item, since_utc)]

    @staticmethod
    def _message_is_since(item: Dict[str, Any], since: datetime) -> bool:
        value = next((item.get(key) for key in (
            "received_at", "receivedAt", "created_at", "createdAt", "date", "timestamp"
        ) if item.get(key)), None)
        if not value:
            return True
        if isinstance(value, datetime):
            timestamp = value
        else:
            try:
                timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            except (TypeError, ValueError):
                return True
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc) >= since

    def get_rental_sms_history(self, phone: str, days_back: int = 7) -> Dict[str, List[Dict[str, Any]]]:
        """Возвращает историю SMS активных rental за последние ``days_back`` дней.

        Это намеренно два запроса — отдельно для renewable и non-renewable,
        как в SDK-примере с двумя списками аренд.
        """
        since = datetime.now(timezone.utc).replace(microsecond=0)
        from datetime import timedelta
        since -= timedelta(days=max(0, days_back))
        return {
            "renewable": self.list_sms(to_number=phone, reservation_type="renewable", since=since),
            "non-renewable": self.list_sms(to_number=phone, reservation_type="non-renewable", since=since),
        }

    def get_rental_sms_by_phone(self, phone: str, days_back: int = 7) -> Dict[str, List[Dict[str, Any]]]:
        """Совместимый алиас для получения истории SMS по номеру."""
        return self.get_rental_sms_history(phone, days_back=days_back)


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