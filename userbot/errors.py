"""Кастомные исключения библиотеки wintergram_userbot."""


class WinterGramError(Exception):
    """Базовое исключение библиотеки."""


class RPCError(WinterGramError):
    """Ошибка, возвращённая сервером в rpc_error.

    ``code`` - числовой код ошибки (int),
    ``message`` - текстовое описание (str).
    """

    def __init__(self, code, message, request_name=None):
        self.code = int(code)
        self.message = message
        self.request_name = request_name
        super().__init__(
            "RPCError {}: {} ({}); code={}".format(
                self.code, self.message, self.request_name or "-", hex(self.code)
            )
        )


class FloodWaitError(RPCError):
    """Ошибка FLOOD_WAIT_X / SLOWMODE_WAIT_X.

    ``seconds`` - сколько секунд ждать клиенту; если не передан,
    извлекается из text ошибки.
    """

    def __init__(self, code, message, seconds=None, request_name=None):
        if seconds is None:
            seconds = 0.0
            for prefix in ("FLOOD_WAIT_", "SLOWMODE_WAIT_"):
                if message.startswith(prefix):
                    try:
                        seconds = float(message[len(prefix):])
                    except ValueError:
                        seconds = 0.0
                    break
        self.seconds = float(seconds)
        super().__init__(code, message, request_name)

    @classmethod
    def from_rpc(cls, rpc_error, request_name=None):
        seconds = 0.0
        try:
            if rpc_error.message.startswith("FLOOD_WAIT_"):
                seconds = float(rpc_error.message[len("FLOOD_WAIT_"):])
            elif rpc_error.message.startswith("SLOWMODE_WAIT_"):
                seconds = float(rpc_error.message[len("SLOWMODE_WAIT_"):])
        except ValueError:
            seconds = 0.0
        return cls(rpc_error.code, rpc_error.message, seconds, request_name)


class AuthKeyError(WinterGramError):
    """Проблема с auth_key / авторизацией ключа (не путать с авторизацией юзера)."""


class LayerMismatchError(WinterGramError):
    """Запрошенный слой не поддерживается библиотекой (вне диапазона 167..228)."""


class UnknownLayerError(LayerMismatchError):
    """Не удалось определить слой сервера по ответу help.getConfig."""


class AuthorizationExpiredError(WinterGramError):
    """Сервер вернул AUTH_KEY_UNREGISTERED / SESSION_REVOKED."""


class ConnectionClosedError(WinterGramError):
    """TCP-соединение закрылось неожиданно."""


class MTProtoVersionError(WinterGramError):
    """Не удалось корректно расшифровать сообщение (msg_key не совпал).

    Обычно означает несовпадение версии протокола (v1/v2) или испорченный ключ.
    """


class TimeoutError(WinterGramError):
    """Превышено время ожидания ответа от сервера."""


class TransportError(WinterGramError):
    """Ошибка транспорта (framing / CRC / соединение)."""


class SchemaError(WinterGramError):
    """Проблемы со схемой слоя."""


class RetryAfterError(RPCError):
    """Сервер просит подождать (заглушка для RATE_LIMIT и пр.)."""


class SessionPasswordNeededError(RPCError):
    """Сервер требует 2FA-пароль (SESSION_PASSWORD_NEEDED / auth check."""
    pass


class PhoneCodeInvalidError(RPCError):
    """Неверный одноразовый код подтверждения (PHONE_CODE_INVALID)."""
    pass


class PhoneNumberUnoccupiedError(RPCError):
    """Номер не зарегистрирован — нужно auth.signUp."""
    pass


class PhoneCodeExpiredError(RPCError):
    """Код истёк (PHONE_CODE_EXPIRED)."""
    pass


class PasswordHashInvalidError(RPCError):
    """Неверный 2FA-пароль (PASSWORD_HASH_INVALID)."""
    pass