"""AWS 세션·클라이언트 생성과 STS 자격 증명 확인."""
from ...errors import Problem


class AwsSession:
    def __init__(self, region, session_factory=None):
        self.region = region
        self._factory = session_factory
        self._session = None
        self._clients = {}
        self.error = None
        self.account_id = None
        self.connected = False
        self._check()

    def _check(self):
        try:
            if self._factory is None:
                import boto3
                self._session = boto3.Session(region_name=self.region)
            else:
                self._session = self._factory(self.region)
            kwargs = {"region_name": self.region}
            try:
                from botocore.config import Config
                kwargs["config"] = Config(connect_timeout=3, read_timeout=3, retries={"max_attempts": 1})
            except ImportError:
                pass
            self.account_id = self._session.client("sts", **kwargs).get_caller_identity().get("Account")
        except Exception as error:
            self.error = type(error).__name__
            self.connected = False
            return
        self.connected = True

    def require_ready(self):
        if not self.connected:
            raise Problem(503, "AWS 데이터 공급자에 연결할 수 없습니다.", "DATA_SOURCE_UNAVAILABLE")

    def client(self, name):
        self.require_ready()
        if name not in self._clients:
            self._clients[name] = self._session.client(name, region_name=self.region)
        return self._clients[name]

    def regional_client(self, name, region):
        """홈 리전이 아닌 리전의 클라이언트(지리별 공격자 SSM 호출용)."""
        self.require_ready()
        key = (name, region)
        if key not in self._clients:
            self._clients[key] = self._session.client(name, region_name=region)
        return self._clients[key]
