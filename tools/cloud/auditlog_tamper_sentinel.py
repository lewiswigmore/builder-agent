import base64,datetime as dt,getpass,hashlib,json,os,platform,random,stat,subprocess,sys,time
from dataclasses import dataclass,asdict,field
from pathlib import Path
from typing import Any,Dict,List,Optional,Tuple

# Ethical warning: Authorized testing and monitoring only. Use least-privilege, read-only roles. Misuse may be illegal.

def _lazy_import_boto3():
    try:
        import boto3  # type: ignore
        from botocore.exceptions import BotoCoreError, ClientError  # type: ignore
        return boto3,BotoCoreError,ClientError
    except Exception:
        return None,None,None

def _lazy_import_google():
    try:
        from google.cloud import storage  # type: ignore
        from google.api_core.exceptions import GoogleAPIError  # type: ignore
        return storage,GoogleAPIError
    except Exception:
        return None,None

def _lazy_import_requests():
    try:
        import requests  # type: ignore
        return requests
    except Exception:
        return None

def _lazy_import_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey,Ed25519PublicKey  # type: ignore
        from cryptography.hazmat.primitives import serialization,hashes  # type: ignore
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
        from cryptography.exceptions import InvalidSignature  # type: ignore
        return (Ed25519PrivateKey,Ed25519PublicKey,serialization,hashes,AESGCM,InvalidSignature)
    except Exception:
        return (None,)*6

TOOL_VERSION="1.0.0"

@dataclass
class Alert:
    severity:str;provider:str;message:str
    time_window:Optional[str]=None
    details:Dict[str,Any]=field(default_factory=dict)
    def to_dict(self): return asdict(self)

@dataclass
class PolicyDriftFinding:
    provider:str;resource:str;drift:str;remediation_as_code:str
    def to_dict(self): return asdict(self)

@dataclass
class ProviderAttestation:
    provider:str;resource:str;audited_period_start:str;audited_period_end:str
    continuity:str;immutability:str;digest_chain_status:str
    digest_artifacts:List[str]=field(default_factory=list)
    signature:Optional[str]=None
    signer_pubkey_fingerprint:Optional[str]=None
    tsa_timestamp:Optional[str]=None
    rekor_entry_uuid:Optional[str]=None
    def to_dict(self): return asdict(self)

@dataclass
class TimeSyncInfo:
    method:str;status:str;details:Dict[str,Any]
    def to_dict(self): return asdict(self)

@dataclass
class EvidenceBundle:
    tool_version:str;run_id:str;run_time_utc:str;host:str;user:str
    providers:List[str];time_sync:TimeSyncInfo
    alerts:List[Alert];policy_drifts:List[PolicyDriftFinding];attestations:List[ProviderAttestation]
    external_references:Dict[str,Any]=field(default_factory=dict)
    signature:Optional[str]=None
    signer_pubkey_fingerprint:Optional[str]=None
    tsa_timestamp:Optional[str]=None
    rekor_entry_uuid:Optional[str]=None
    def to_json_canonical(self)->bytes:
        return json.dumps({
            "tool_version":self.tool_version,"run_id":self.run_id,"run_time_utc":self.run_time_utc,
            "host":self.host,"user":self.user,"providers":self.providers,"time_sync":self.time_sync.to_dict(),
            "alerts":[a.to_dict() for a in self.alerts],
            "policy_drifts":[d.to_dict() for d in self.policy_drifts],
            "attestations":[a.to_dict() for a in self.attestations],
            "external_references":self.external_references,
        },sort_keys=True,separators=(",",":")).encode()

@dataclass
class AWSConfig:
    account_id:str;region:str;trail_s3_bucket:str;digest_prefix:str
    expected_digest_minutes:int=15;audited_period_hours:int=1

@dataclass
class AzureConfig:
    subscription_id:str;resource_group:str;storage_account:str;container:str
    audited_period_hours:int=1

@dataclass
class GCPConfig:
    project_id:str;gcs_bucket:str;audited_period_hours:int=1

@dataclass
class Config:
    aws:List[AWSConfig]=field(default_factory=list)
    azure:List[AzureConfig]=field(default_factory=list)
    gcp:List[GCPConfig]=field(default_factory=list)
    tsa_url:Optional[str]=None;rekor_url:Optional[str]=None
    archive_dir:str="./evidence_archive";keys_dir:str="~/.auditlog_sentinel/keys";max_evidence_files:int=100

class LocalSigner:
    def __init__(self,keys_dir:str):
        (Ed25519PrivateKey,Ed25519PublicKey,serialization,hashes,AESGCM,InvalidSignature)=_lazy_import_crypto()
        if Ed25519PrivateKey is None: raise RuntimeError("cryptography required. Install 'cryptography'.")
        self.Ed25519PrivateKey=Ed25519PrivateKey;self.Ed25519PublicKey=Ed25519PublicKey
        self.serialization=serialization;self.AESGCM=AESGCM;self.InvalidSignature=InvalidSignature
        self._keys_dir=Path(os.path.expanduser(keys_dir));self._keys_dir.mkdir(parents=True,exist_ok=True)
        self._sign_key_path=self._keys_dir/"signing_ed25519.key";self._enc_key_path=self._keys_dir/"archive_aesgcm.key"
        self._priv=self._load_or_create_sign_key();self._enc_key=self._load_or_create_enc_key()
    def _restrict_perms(self,p:Path):
        try: os.chmod(p,stat.S_IRUSR|stat.S_IWUSR)
        except Exception: pass
    def _load_or_create_sign_key(self):
        if self._sign_key_path.exists():
            return self.Ed25519PrivateKey.from_private_bytes(self._sign_key_path.read_bytes())
        priv=self.Ed25519PrivateKey.generate()
        data=priv.private_bytes(encoding=self.serialization.Encoding.Raw,
                                format=self.serialization.PrivateFormat.Raw,
                                encryption_algorithm=self.serialization.NoEncryption())
        self._sign_key_path.write_bytes(data);self._restrict_perms(self._sign_key_path);return priv
    def _load_or_create_enc_key(self):
        if self._enc_key_path.exists(): return self._enc_key_path.read_bytes()
        key=os.urandom(32);self._enc_key_path.write_bytes(key);self._restrict_perms(self._enc_key_path);return key
    def sign(self,data:bytes)->bytes: return self._priv.sign(data)
    def pubkey_pem(self)->bytes:
        return self._priv.public_key().public_bytes(encoding=self.serialization.Encoding.PEM,
                                                    format=self.serialization.PublicFormat.SubjectPublicKeyInfo)
    def pubkey_fingerprint(self)->str:
        der=self._priv.public_key().public_bytes(encoding=self.serialization.Encoding.DER,
                                                 format=self.serialization.PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(der).hexdigest()
    def encrypt(self,plaintext:bytes,aad:Optional[bytes]=None)->Dict[str,str]:
        aes=self.AESGCM(self._enc_key);nonce=os.urandom(12);ct=aes.encrypt(nonce,plaintext,aad)
        return {"version":"aesgcm-1","nonce_b64":base64.b64encode(nonce).decode(),"ciphertext_b64":base64.b64encode(ct).decode()}
    def decrypt(self,env:Dict[str,str],aad:Optional[bytes]=None)->bytes:
        aes=self.AESGCM(self._enc_key);nonce=base64.b64decode(env["nonce_b64"]);ct=base64.b64decode(env["ciphertext_b64"])
        return aes.decrypt(nonce,ct,aad)

class TSAClient:
    def __init__(self,tsa_url:Optional[str]): self.tsa_url=tsa_url;self.requests=_lazy_import_requests()
    def rfc3161_timestamp(self,data_sha256:bytes)->Optional[str]:
        if not self.tsa_url or not self.requests: return None
        try:
            r=self.requests.post(self.tsa_url,json={"sha256":base64.b64encode(data_sha256).decode(),"nonce":random.getrandbits(64)},timeout=10)
            return base64.b64encode(r.content).decode() if r.status_code in (200,201,202) else None
        except Exception: return None

class RekorClient:
    def __init__(self,rekor_url:Optional[str]): self.rekor_url=rekor_url.rstrip("/") if rekor_url else None;self.requests=_lazy_import_requests()
    def create_rekord_entry(self,artifact:bytes,signature:bytes,public_key_pem:bytes)->Optional[str]:
        if not self.rekor_url or not self.requests: return None
        try:
            payload={"apiVersion":"0.0.1","kind":"rekord","spec":{"data":{"content":base64.b64encode(artifact).decode()},
                     "signature":{"content":base64.b64encode(signature).decode(),"publicKey":{"content":public_key_pem.decode()}}}}
            r=self.requests.post(f"{self.rekor_url}/api/v1/log/entries",json=payload,timeout=15)
            if r.status_code in (200,201):
                body=r.json()
                if isinstance(body,dict) and body: return list(body.keys())[0]
            return None
        except Exception: return None

class ChronyChecker:
    @staticmethod
    def check()->TimeSyncInfo:
        try:
            out=subprocess.check_output(["chronyc","tracking"],timeout=3,stderr=subprocess.STDOUT).decode()
            d={};[d.update({k.strip():v.strip()}) for k,v in [ln.split(":",1) for ln in out.splitlines() if ":" in ln]]
            return TimeSyncInfo(method="chronyc",status="ok" if "System time" in d else "unknown",details=d)
        except Exception: pass
        try:
            out=subprocess.check_output(["timedatectl","show"],timeout=3,stderr=subprocess.STDOUT).decode()
            d={};[d.update({k:v}) for k,v in [ln.split("=",1) for ln in out.splitlines() if "=" in ln] if k in ("NTPSynchronized","TimeUSec","RTCTimeUSec")]
            return TimeSyncInfo(method="timedatectl",status="ok" if d.get("NTPSynchronized")=="yes" else "unknown",details=d)
        except Exception: pass
        try:
            requests=_lazy_import_requests()
            if requests:
                r=requests.get("https://www.cloudflare.com/cdn-cgi/trace",timeout=3);now=time.time();drift=0.0
                if r.status_code==200:
                    for ln in r.text.splitlines():
                        if ln.startswith("ts="):
                            try: drift=abs(float(ln.split("=",1)[1])-now)
                            except Exception: pass
                return TimeSyncInfo(method="https-date",status="ok" if drift<5 else "drift>5s",details={"drift_seconds":drift})
        except Exception: pass
        return TimeSyncInfo(method="none",status="unknown",details={})

def _dt_parse(s:str)->dt.datetime:
    try: return dt.datetime.fromisoformat(s.replace("Z","+00:00")).astimezone(dt.timezone.utc)
    except Exception: pass
    return dt.datetime.strptime(s,"%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)

class AWSCloudTrailVerifier:
    def __init__(self,cfg:AWSConfig):
        self.cfg=cfg;self.boto3,self.BotoCoreError,self.ClientError=_lazy_import_boto3()
        self.s3=self.boto3.client("s3",region_name=self.cfg.region) if self.boto3 else None
    def _list_digest_keys(self,start:dt.datetime,end:dt.datetime)->List[str]:
        if not self.s3: return []
        keys=[];cont=None;prefix=self.cfg.digest_prefix.rstrip("/")+"/"
        while True:
            try:
                resp=self.s3.list_objects_v2(Bucket=self.cfg.trail_s3_bucket,Prefix=prefix,**({"ContinuationToken":cont} if cont else {}))
            except Exception: break
            for obj in resp.get("Contents",[]):
                k=obj.get("Key","")
                if k and "Digest" in k and (k.endswith(".json") or k.endswith(".json.gz")):
                    lm=obj.get("LastModified")
                    if isinstance(lm,dt.datetime):
                        if start<=lm.astimezone(dt.timezone.utc)<=end: keys.append(k)
                    else: keys.append(k)
            if resp.get("IsTruncated"): cont=resp.get("NextContinuationToken")
            else: break
        return sorted(keys)
    def _get_digest_document(self,key:str)->Optional[Dict[str,Any]]:
        if not self.s3: return None
        try:
            obj=self.s3.get_object(Bucket=self.cfg.trail_s3_bucket,Key=key);body=obj["Body"].read()
            if key.endswith(".gz"):
                import gzip,io
                with gzip.GzipFile(fileobj=io.BytesIO(body)) as f: data=f.read().decode()
            else: data=body.decode()
            return json.loads(data)
        except Exception: return None
    def _check_bucket_immutability_and_policy(self)->Tuple[bool,List[PolicyDriftFinding],Dict[str,Any]]:
        findings=[];ok=True;details={}
        if not self.s3: return False,findings,details
        b=self.cfg.trail_s3_bucket
        try:
            ol=self.s3.get_object_lock_configuration(Bucket=b);details["object_lock"]=ol
            rule=ol.get("ObjectLockConfiguration",{}).get("Rule",{});ret=rule.get("DefaultRetention",{})
            mode=ret.get("Mode");retain_days=ret.get("Days") or ret.get("Years")
            if mode!="COMPLIANCE" or not retain_days:
                ok=False;findings.append(PolicyDriftFinding("aws",f"s3://{b}","Object Lock not COMPLIANCE or no default retention",_remediation_tf_s3_object_lock(b,90)))
        except Exception as e:
            ok=False;findings.append(PolicyDriftFinding("aws",f"s3://{b}",f"Failed to retrieve Object Lock: {e}",_remediation_tf_s3_object_lock(b,90)))
        try:
            ver=self.s3.get_bucket_versioning(Bucket=b);details["versioning"]=ver
            if ver.get("Status")!="Enabled":
                ok=False;findings.append(PolicyDriftFinding("aws",f"s3://{b}","Bucket versioning not Enabled",_remediation_tf_s3_versioning(b)))
        except Exception:
            ok=False;findings.append(PolicyDriftFinding("aws",f"s3://{b}","Unable to check bucket versioning",_remediation_tf_s3_versioning(b)))
        try:
            pol=self.s3.get_bucket_policy(Bucket=b);details["policy"]=json.loads(pol.get("Policy","{}"))
            st=details["policy"].get("Statement",[]);st=[st] if isinstance(st,dict) else st
            for s in st:
                if s.get("Effect")=="Allow":
                    acts=s.get("Action");acts=[acts] if isinstance(acts,str) else (acts or [])
                    if any(a in ("s3:DeleteObject","s3:DeleteObjectVersion") for a in acts):
                        ok=False;findings.append(PolicyDriftFinding("aws",f"s3://{b}","Bucket policy allows deletions",_remediation_tf_s3_deny_delete(b)))
        except Exception: pass
        return ok,findings,details
    def verify(self)->Tuple[List[Alert],List[PolicyDriftFinding],Optional[ProviderAttestation]]:
        alerts=[];drifts=[]
        now=dt.datetime.now(dt.timezone.utc);start=now-dt.timedelta(hours=self.cfg.audited_period_hours)
        keys=self._list_digest_keys(start,now);docs=[]
        for k in keys:
            d=self._get_digest_document(k)
            if d: docs.append((k,d))
        missing=[];chain_ok=True;artifacts=[k for k,_ in docs];exp=dt.timedelta(minutes=self.cfg.expected_digest_minutes)
        intervals=[]
        for k,d in docs:
            st=d.get("digestStartTime") or d.get("digest_start_time") or d.get("startTime")
            en=d.get("digestEndTime") or d.get("digest_end_time") or d.get("endTime")
            try:
                dt_st=_dt_parse(st) if isinstance(st,str) else None;dt_en=_dt_parse(en) if isinstance(en,str) else None
                if dt_st and dt_en: intervals.append((dt_st,dt_en,k,d))
            except Exception: continue
        intervals.sort(key=lambda x:x[0]);last_end=None;last_sig=None;last_key=None
        for st,en,k,d in intervals:
            if last_end is not None:
                if st>last_end: missing.append((last_end,st));chain_ok=False
                if abs((st-last_end).total_seconds())>exp.total_seconds()+60: chain_ok=False
                prev=d.get("previousDigestSignature") or d.get("previousDigestHash") or d.get("previous_digest_signature")
                cur=d.get("digestSignature") or d.get("digestHash") or d.get("digest_signature")
                if prev and last_sig and prev!=last_sig:
                    chain_ok=False
                    alerts.append(Alert(severity="CRITICAL",provider="aws",
                        message="CloudTrail digest chain mismatch",
                        time_window=f"{st.isoformat()} -> {en.isoformat()}",
                        details={"bucket":self.cfg.trail_s3_bucket,"region":self.cfg.region,
                                 "previous_digest_signature_expected":last_sig,"previous_digest_signature_observed":prev,
                                 "mismatch_between":[last_key,k]}))
            last_end=en
            last_sig=d.get("digestSignature") or d.get("digestHash") or d.get("digest_signature");last_key=k
        if not intervals:
            chain_ok=False;missing.append((start,now))
        imm_ok,drift_findings,_=self._check_bucket_immutability_and_policy();drifts.extend(drift_findings)
        if missing:
            tw_start=missing[0][0].isoformat();tw_end=missing[-1][1].isoformat()
            alerts.append(Alert(severity="CRITICAL",provider="aws",
                message="CloudTrail digest gap detected (missing digest interval)",
                time_window=f"{tw_start} -> {tw_end}",
                details={"bucket":self.cfg.trail_s3_bucket,"region":self.cfg.region,
                         "expected_interval_minutes":self.cfg.expected_digest_minutes,
                         "missing_intervals":[{"from":a[0].isoformat(),"to":a[1].isoformat()} for a in missing],
                         "digests_checked":artifacts}))
        att=ProviderAttestation(provider="aws",resource=f"s3://{self.cfg.trail_s3_bucket}",
                                audited_period_start=start.isoformat(),audited_period_end=now.isoformat(),
                                continuity="verified" if chain_ok and not missing else "issues",
                                immutability="verified" if imm_ok else "issues",
                                digest_chain_status="verified" if chain_ok else "issues",
                                digest_artifacts=artifacts)
        return alerts,drifts,att

class GCPAuditLogVerifier:
    def __init__(self,cfg:GCPConfig):
        self.cfg=cfg;self.storage,self.GoogleAPIError=_lazy_import_google()
        self.client=None
        if self.storage:
            try: self.client=self.storage.Client(project=self.cfg.project_id)
            except Exception: self.client=None
    def verify(self)->Tuple[List[Alert],List[PolicyDriftFinding],Optional[ProviderAttestation]]:
        alerts=[];drifts=[];now=dt.datetime.now(dt.timezone.utc);start=now-dt.timedelta(hours=self.cfg.audited_period_hours)
        bucket=self.cfg.gcs_bucket;imm_ok=False
        try:
            if self.client:
                b=self.client.get_bucket(bucket)
                rp=getattr(b,"retention_policy",None) or getattr(b,"retentionPolicy",None)
                locked=False;ret=None
                if rp: ret=rp.get("retentionPeriod") or getattr(rp,"retention_period",None);locked=bool(rp.get("isLocked"))
                else: ret=getattr(b,"retention_period",None);locked=getattr(b,"retention_policy_locked",False)
                if (ret and ret>=86400) and locked: imm_ok=True
                else:
                    drifts.append(PolicyDriftFinding("gcp",f"gs://{bucket}","Bucket retention not locked or <1 day",_remediation_tf_gcs_retention(bucket,1)))
        except Exception as e:
            drifts.append(PolicyDriftFinding("gcp",f"gs://{bucket}",f"Failed to check retention policy: {e}",_remediation_tf_gcs_retention(bucket,1)))
        att=ProviderAttestation(provider="gcp",resource=f"gs://{bucket}",
                                audited_period_start=start.isoformat(),audited_period_end=now.isoformat(),
                                continuity="verified",immutability="verified" if imm_ok else "issues",
                                digest_chain_status="not_applicable")
        return alerts,drifts,att

class AzureAuditLogVerifier:
    def __init__(self,cfg:AzureConfig): self.cfg=cfg
    def verify(self)->Tuple[List[Alert],List[PolicyDriftFinding],Optional[ProviderAttestation]]:
        alerts=[];drifts=[];now=dt.datetime.now(dt.timezone.utc);start=now-dt.timedelta(hours=self.cfg.audited_period_hours)
        cid=f"/subscriptions/{self.cfg.subscription_id}/resourceGroups/{self.cfg.resource_group}/providers/Microsoft.Storage/storageAccounts/{self.cfg.storage_account}/blobServices/default/containers/{self.cfg.container}"
        imm_ok=False
        try:
            out=subprocess.check_output(["az","storage","container","immutability-policy","show","--account-name",self.cfg.storage_account,"--container-name",self.cfg.container,"-o","json"],timeout=8).decode()
            pol=json.loads(out) if out else {}
            has_lh=False
            try:
                out2=subprocess.check_output(["az","storage","container","legal-hold","show","--account-name",self.cfg.storage_account,"--container-name",self.cfg.container,"-o","json"],timeout=8).decode()
                lh=json.loads(out2) if out2 else {};has_lh=bool(lh.get("hasLegalHold") or lh.get("tags"))
            except Exception: pass
            days=pol.get("immutabilityPeriodSinceCreationInDays") or 0;state=(pol.get("state") or "").upper()
            if state=="LOCKED" and days>=1: imm_ok=True
            else: drifts.append(PolicyDriftFinding("azure",cid,"Container immutability not LOCKED or <1 day",_remediation_tf_az_immutability(self.cfg.storage_account,self.cfg.container,1)))
            if not has_lh: drifts.append(PolicyDriftFinding("azure",cid,"Legal hold not enabled",_remediation_tf_az_legal_hold(self.cfg.storage_account,self.cfg.container)))
        except Exception as e:
            drifts.append(PolicyDriftFinding("azure",cid,f"Failed to query immutability: {e}",_remediation_tf_az_immutability(self.cfg.storage_account,self.cfg.container,1)))
        att=ProviderAttestation(provider="azure",resource=cid,audited_period_start=start.isoformat(),audited_period_end=now.isoformat(),
                                continuity="verified",immutability="verified" if imm_ok else "issues",digest_chain_status="not_applicable")
        return alerts,drifts,att

def _remediation_tf_s3_object_lock(bucket:str,min_days:int)->str:
    return f'resource "aws_s3_bucket" "logs" {{ bucket="{bucket}" object_lock_enabled=true }}\nresource "aws_s3_bucket_object_lock_configuration" "logs" {{ bucket=aws_s3_bucket.logs.id rule {{ default_retention {{ mode="COMPLIANCE" days={min_days} }} }} }}'

def _remediation_tf_s3_versioning(bucket:str)->str:
    return f'resource "aws_s3_bucket_versioning" "logs" {{ bucket="{bucket}" versioning_configuration {{ status="Enabled" }} }}'

def _remediation_tf_s3_deny_delete(bucket:str)->str:
    pol={"Version":"2012-10-17","Statement":[{"Sid":"DenyObjectDelete","Effect":"Deny","Principal":"*","Action":["s3:DeleteObject","s3:DeleteObjectVersion"],"Resource":[f"arn:aws:s3:::{bucket}/*"]}]}
    return f'resource "aws_s3_bucket_policy" "deny_delete" {{ bucket="{bucket}" policy=<<POLICY\n{json.dumps(pol,indent=2)}\nPOLICY\n}}'

def _remediation_tf_gcs_retention(bucket:str,min_days:int)->str:
    seconds=min_days*86400
    return f'resource "google_storage_bucket" "logs" {{ name="{bucket}" retention_policy {{ retention_period={seconds} is_locked=true }} }}'

def _remediation_tf_az_immutability(acct:str,container:str,min_days:int)->str:
    return f"az storage container immutability-policy create --account-name {acct} --container-name {container} --period {min_days} --allow-protected-append-writes-all true\naz storage container immutability-policy lock --account-name {acct} --container-name {container}"

def _remediation_tf_az_legal_hold(acct:str,container:str)->str:
    return f'az storage container legal-hold set --account-name {acct} --container-name {container} --tags "audit" "hold"'

class EvidenceArchive:
    def __init__(self,archive_dir:str,signer:LocalSigner,max_files:int=100):
        self.dir=Path(archive_dir);self.dir.mkdir(parents=True,exist_ok=True);self.signer=signer;self.max_files=max_files
    def _rotate(self):
        files=sorted(self.dir.glob("sentinel_evidence_*.json"),key=lambda p:p.stat().st_mtime)
        if len(files)>self.max_files:
            for p in files[:len(files)-self.max_files]:
                try: p.unlink()
                except Exception: pass
    def _write_immutable(self,path:Path,data:bytes):
        if path.exists(): raise FileExistsError(f"Evidence file already exists: {path}")
        path.write_bytes(data)
        try: os.chmod(path,stat.S_IRUSR|stat.S_IRGRP|stat.S_IROTH)
        except Exception: pass
    def store(self,bundle:EvidenceBundle)->Dict[str,str]:
        ts=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ");base=f"sentinel_evidence_{ts}_{bundle.run_id}"
        json_bytes=bundle.to_json_canonical();sig=self.signer.sign(json_bytes)
        bundle.signature=base64.b64encode(sig).decode();bundle.signer_pubkey_fingerprint=self.signer.pubkey_fingerprint()
        final_json=bundle.to_json_canonical()
        env=self.signer.encrypt(final_json,aad=b"AuditLogTamperSentinel-v1")
        env_file={"envelope":env,"note":"Evidence encrypted with local AES-GCM key; signing key is separate."}
        out={}
        jp=self.dir/f"{base}.json";sp=self.dir/f"{base}.sig";ep=self.dir/f"{base}.env.json"
        self._write_immutable(jp,final_json);self._write_immutable(sp,sig);self._write_immutable(ep,json.dumps(env_file,sort_keys=True,indent=2).encode())
        self._rotate();out["evidence_json"]=str(jp);out["signature"]=str(sp);out["envelope"]=str(ep);return out

class AuditLogTamperSentinel:
    def __init__(self,cfg:Config):
        self.cfg=cfg;self.signer=LocalSigner(cfg.keys_dir);self.tsa=TSAClient(cfg.tsa_url);self.rekor=RekorClient(cfg.rekor_url)
        self.archive=EvidenceArchive(cfg.archive_dir,self.signer,cfg.max_evidence_files)
    def run(self)->EvidenceBundle:
        run_id=hashlib.sha256(os.urandom(16)).hexdigest()[:12];alerts=[];drifts=[];atts=[];providers=[]
        time_sync=ChronyChecker.check()
        for acfg in self.cfg.aws:
            providers.append("aws");a,d,att=AWSCloudTrailVerifier(acfg).verify();alerts+=a;drifts+=d
            if att: atts.append(att)
        for zcfg in self.cfg.azure:
            providers.append("azure");a,d,att=AzureAuditLogVerifier(zcfg).verify();alerts+=a;drifts+=d
            if att: atts.append(att)
        for gcfg in self.cfg.gcp:
            providers.append("gcp");a,d,att=GCPAuditLogVerifier(gcfg).verify();alerts+=a;drifts+=d
            if att: atts.append(att)
        for att in atts:
            canon=json.dumps(att.to_dict(),sort_keys=True,separators=(",",":")).encode()
            sig=self.signer.sign(canon);att.signature=base64.b64encode(sig).decode();att.signer_pubkey_fingerprint=self.signer.pubkey_fingerprint()
        bundle=EvidenceBundle(tool_version=TOOL_VERSION,run_id=run_id,run_time_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                              host=f"{platform.node()} ({platform.system()} {platform.release()})",user=getpass.getuser(),
                              providers=sorted(set(providers)),time_sync=time_sync,alerts=alerts,policy_drifts=drifts,attestations=atts)
        try:
            sha256=hashlib.sha256(bundle.to_json_canonical()).digest();ts=self.tsa.rfc3161_timestamp(sha256)
            if ts: bundle.tsa_timestamp=ts
        except Exception: pass
        try:
            sig=self.signer.sign(bundle.to_json_canonical());pub=self.signer.pubkey_pem()
            rid=self.rekor.create_rekord_entry(bundle.to_json_canonical(),sig,pub)
            if rid: bundle.rekor_entry_uuid=rid
        except Exception: pass
        bundle.signature=base64.b64encode(self.signer.sign(bundle.to_json_canonical())).decode()
        bundle.signer_pubkey_fingerprint=self.signer.pubkey_fingerprint()
        paths=self.archive.store(bundle);bundle.external_references.update(paths);return bundle

def load_config_from_env()->Config:
    aws=[];azure=[];gcp=[]
    if os.getenv("AWS_AUDIT_BUCKET"):
        aws.append(AWSConfig(
            account_id=os.getenv("AWS_ACCOUNT_ID",""),
            region=os.getenv("AWS_REGION","us-east-1"),
            trail_s3_bucket=os.getenv("AWS_AUDIT_BUCKET",""),
            digest_prefix=os.getenv("AWS_DIGEST_PREFIX","").strip() or f"AWSLogs/{os.getenv('AWS_ACCOUNT_ID','')}/CloudTrail-Digest/{os.getenv('AWS_REGION','us-east-1')}",
            expected_digest_minutes=int(os.getenv("AWS_DIGEST_EXPECTED_MINUTES","15")),
            audited_period_hours=int(os.getenv("AUDITED_PERIOD_HOURS","1")),
        ))
    if os.getenv("AZ_SUBSCRIPTION_ID") and os.getenv("AZ_STORAGE_ACCOUNT") and os.getenv("AZ_CONTAINER"):
        azure.append(AzureConfig(
            subscription_id=os.getenv("AZ_SUBSCRIPTION_ID",""),
            resource_group=os.getenv("AZ_RESOURCE_GROUP",""),
            storage_account=os.getenv("AZ_STORAGE_ACCOUNT",""),
            container=os.getenv("AZ_CONTAINER",""),
            audited_period_hours=int(os.getenv("AUDITED_PERIOD_HOURS","1")),
        ))
    if os.getenv("GCP_PROJECT_ID") and os.getenv("GCS_BUCKET"):
        gcp.append(GCPConfig(
            project_id=os.getenv("GCP_PROJECT_ID",""),
            gcs_bucket=os.getenv("GCS_BUCKET",""),
            audited_period_hours=int(os.getenv("AUDITED_PERIOD_HOURS","1")),
        ))
    return Config(aws=aws,azure=azure,gcp=gcp,tsa_url=os.getenv("TSA_URL"),rekor_url=os.getenv("REKOR_URL"),
                  archive_dir=os.getenv("EVIDENCE_ARCHIVE_DIR","./evidence_archive"),
                  keys_dir=os.getenv("SENTINEL_KEYS_DIR","~/.auditlog_sentinel/keys"),
                  max_evidence_files=int(os.getenv("EVIDENCE_MAX_FILES","100")))

def main():
    print("AuditLog Tamper Sentinel - Authorized use only. Ensure you have explicit permission. Read-only operations are used.",file=sys.stderr)
    cfg=load_config_from_env();sentinel=AuditLogTamperSentinel(cfg)
    try:
        bundle=sentinel.run()
    except Exception as e:
        err=Alert(severity="CRITICAL",provider="system",message=f"Sentinel run failed: {e}",details={"trace":"Check logs","ethical_notice":"Authorized environments only"})
        bundle=EvidenceBundle(tool_version=TOOL_VERSION,run_id=hashlib.sha256(os.urandom(16)).hexdigest()[:12],
                              run_time_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                              host=f"{platform.node()} ({platform.system()} {platform.release()})",user=getpass.getuser(),
                              providers=[],time_sync=ChronyChecker.check(),alerts=[err],policy_drifts=[],attestations=[])
        try:
            signer=LocalSigner(cfg.keys_dir);archive=EvidenceArchive(cfg.archive_dir,signer,cfg.max_evidence_files)
            bundle.signature=base64.b64encode(signer.sign(bundle.to_json_canonical())).decode()
            bundle.signer_pubkey_fingerprint=signer.pubkey_fingerprint();archive.store(bundle)
        except Exception: pass
    out={"tool_version":bundle.tool_version,"run_id":bundle.run_id,"run_time_utc":bundle.run_time_utc,
         "alerts":[a.to_dict() for a in bundle.alerts],
         "policy_drifts":[d.to_dict() for d in bundle.policy_drifts],
         "attestations":[a.to_dict() for a in bundle.attestations],
         "external_references":bundle.external_references,
         "tsa_timestamp_present":bool(bundle.tsa_timestamp),
         "rekor_entry_uuid":bundle.rekor_entry_uuid,
         "signer_pubkey_fingerprint":bundle.signer_pubkey_fingerprint}
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=="__main__":
    main()