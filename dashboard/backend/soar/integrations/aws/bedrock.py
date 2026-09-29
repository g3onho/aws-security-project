"""Amazon Bedrock Converse 호출(대시보드 도우미). boto3 는 이 파일 안에만 둔다.

모델 응답 원문(dict)을 그대로 돌려주고, AWS 오류는 내부 정보 없이 공통 Problem 으로 바꾼다.
"""
from ...errors import Problem


class BedrockChat:
    def __init__(self, aws, model_id, region):
        self._aws = aws
        self.model_id = model_id
        self.region = region
        self._client = None

    def _bedrock(self):
        if self._client is None:
            from botocore.config import Config
            # 도구를 여러 번 부르는 대화라 기본 3초 읽기 제한으로는 부족하다. 재시도는 한 번만(비용·지연 폭주 방지).
            self._client = self._aws.client_with("bedrock-runtime", region=self.region,
                                                 config=Config(connect_timeout=5, read_timeout=45, retries={"max_attempts": 2}))
        return self._client

    def converse(self, system, messages, tool_config, max_tokens):
        try:
            return self._bedrock().converse(
                modelId=self.model_id, system=[{"text": system}], messages=messages, toolConfig=tool_config,
                inferenceConfig={"maxTokens": max_tokens, "temperature": 0.2})
        except Exception as error:  # noqa: BLE001
            code = getattr(error, "response", {}).get("Error", {}).get("Code", type(error).__name__) \
                if hasattr(error, "response") else type(error).__name__
            if code in {"AccessDeniedException", "UnrecognizedClientException"}:
                raise Problem(503, "AI 도우미를 쓸 권한이 없습니다. 대시보드 IAM 에 bedrock:InvokeModel 이 필요합니다.",
                              "ASSISTANT_FORBIDDEN")
            if code in {"ThrottlingException", "ServiceQuotaExceededException", "TooManyRequestsException"}:
                raise Problem(429, "AI 호출이 몰려 잠시 제한됐습니다. 잠시 후 다시 시도하세요.", "RATE_LIMITED")
            raise Problem(502, f"AI 응답을 받지 못했습니다({code}).", "ASSISTANT_UPSTREAM_FAILED")
