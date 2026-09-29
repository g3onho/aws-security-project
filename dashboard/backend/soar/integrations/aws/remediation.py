"""대시보드 원클릭 조치의 AWS 경계: SSM Automation 시작, 조치 전 대상 확인, 같은 기준의 재검증 측정.

이 파일의 쓰기는 ssm:StartAutomationExecution 하나뿐이다(문서가 실제 변경을 한다). 재검증은 읽기 호출만 쓴다.
읽기 권한이 없으면 '통과'가 아니라 예외로 알린다 — 서비스가 재검증 오류로 기록한다.
"""
import hashlib

from botocore.exceptions import ClientError

PUBLIC_ACCESS_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
IAM_REQUIRED = ("RequireSymbols", "RequireNumbers", "RequireUppercaseCharacters", "RequireLowercaseCharacters")
SNAPSHOT_STATE = "block-all-sharing"


def _open_rule(permission):
    return (any(r.get("CidrIp") == "0.0.0.0/0" for r in permission.get("IpRanges", []))
            or any(r.get("CidrIpv6") == "::/0" for r in permission.get("Ipv6Ranges", [])))


class RemediationGateway:
    def __init__(self, session, automation_role_arn, account_id):
        self._session = session
        self.automation_role_arn = automation_role_arn
        self.account_id = account_id

    def describe_group(self, group_id):
        """{vpc, name, tags, inbound, outbound}. 없으면 None."""
        try:
            groups = self._session.client("ec2").describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") == "InvalidGroup.NotFound":
                return None
            raise
        if not groups:
            return None
        group = groups[0]
        return {"vpc": group.get("VpcId"), "name": group.get("GroupName"),
                "tags": {t["Key"]: t["Value"] for t in group.get("Tags", [])},
                "inbound": group.get("IpPermissions", []), "outbound": group.get("IpPermissionsEgress", [])}

    def start(self, document, parameters, seed):
        """같은 seed 의 재시도는 SSM 이 같은 실행으로 돌려준다(ClientToken). 응답을 잃어도 중복 실행되지 않는다."""
        params = {key: [value] for key, value in parameters.items()}
        params["AutomationAssumeRole"] = [self.automation_role_arn]
        token = hashlib.sha256(seed.encode()).hexdigest()[:32]
        return self._session.client("ssm").start_automation_execution(
            DocumentName=document, Parameters=params, ClientToken=token)["AutomationExecutionId"]

    def measure(self, document, parameters):
        """조치 기준 그대로 지금 상태를 읽는다 → {compliant, text}. 읽지 못하면 예외."""
        ec2, ssm = self._session.client("ec2"), self._session.client("ssm")
        if document == "ASR-RemoveDefaultSgRules":
            group = self.describe_group(parameters["SecurityGroupId"])
            if group is None:
                raise LookupError("보안그룹을 찾을 수 없습니다.")
            inbound, outbound = len(group["inbound"]), len(group["outbound"])
            return {"compliant": inbound == 0 and outbound == 0, "text": f"인바운드 {inbound}개 · 아웃바운드 {outbound}개 규칙"}
        if document == "ASR-RevokeSecurityGroupIngress":
            group = self.describe_group(parameters["SecurityGroupId"])
            if group is None:
                raise LookupError("보안그룹을 찾을 수 없습니다.")
            opened = sum(_open_rule(p) for p in group["inbound"])
            return {"compliant": opened == 0, "text": f"전체 공개 인바운드 규칙 {opened}개"}
        if document == "ASR-EnableEbsDefaultEncryption":
            on = bool(ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"])
            return {"compliant": on, "text": f"EBS 기본 암호화: {'켜짐' if on else '꺼짐'}"}
        if document == "ASR-BlockEbsSnapshotPublicAccess":
            state = ec2.get_snapshot_block_public_access_state()["State"]
            return {"compliant": state == SNAPSHOT_STATE, "text": f"스냅샷 퍼블릭 액세스 차단={state}"}
        if document == "ASR-BlockS3AccountPublicAccess":
            try:
                config = self._session.client("s3control").get_public_access_block(
                    AccountId=self.account_id)["PublicAccessBlockConfiguration"]
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") != "NoSuchPublicAccessBlockConfiguration":
                    raise
                config = {}
            on = sum(bool(config.get(key)) for key in PUBLIC_ACCESS_KEYS)
            return {"compliant": on == len(PUBLIC_ACCESS_KEYS), "text": f"S3 퍼블릭 액세스 차단 {on}/{len(PUBLIC_ACCESS_KEYS)}개 켜짐"}
        if document == "ASR-SetIamPasswordPolicy":
            try:
                policy = self._session.client("iam").get_account_password_policy()["PasswordPolicy"]
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") != "NoSuchEntity":
                    raise
                policy = {}
            ok = policy.get("MinimumPasswordLength", 0) >= 8 and all(policy.get(key) for key in IAM_REQUIRED)
            return {"compliant": ok, "text": f"최소 길이 {policy.get('MinimumPasswordLength', '미설정')} · 복잡도 요구 "
                                             f"{sum(bool(policy.get(key)) for key in IAM_REQUIRED)}/4"}
        if document == "ASR-EnableSsmAutomationLogging":
            region = self._session.region
            setting = (f"arn:aws:ssm:{region}:{self.account_id}:servicesetting/ssm/automation/customer-script-log-destination")
            value = ssm.get_service_setting(SettingId=setting)["ServiceSetting"]["SettingValue"]
            return {"compliant": value == "CloudWatch", "text": f"스크립트 로그 대상={value}"}
        if document == "ASR-BlockSsmDocumentPublicSharing":
            value = ssm.get_service_setting(
                SettingId="/ssm/documents/console/public-sharing-permission")["ServiceSetting"]["SettingValue"]
            return {"compliant": value == "Disable", "text": f"공개 공유 권한={value}"}
        raise ValueError("재검증 방법이 없는 문서입니다.")
